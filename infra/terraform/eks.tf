data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}

locals {
  gha_apply_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name}-gha-apply"
  # Built as a static string (not aws_iam_role.cluster_admin.arn) so it is known
  # at plan time: it is used as a for_each key below, which EKS requires.
  cluster_admin_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name}-cluster-admin"
  # The dedicated cluster-admin role is always an admin. The deploying identity
  # and any extra ARNs are added too, except the root user (EKS access entries
  # reject root) -- root reaches the cluster by assuming cluster_admin instead.
  cluster_admin_arns = [
    for arn in distinct(concat(
      [local.cluster_admin_role_arn, data.aws_iam_session_context.current.issuer_arn, local.gha_apply_role_arn],
      var.cluster_admin_arns,
    )) : arn if !endswith(arn, ":root")
  ]
}

module "eks" {
  #checkov:skip=CKV_TF_1:Registry module pinned by version constraint; Dependabot tracks updates
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.31"

  cluster_name    = "${local.name}-eks"
  cluster_version = var.cluster_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # API endpoint: private for nodes, public only for your IP.
  cluster_endpoint_private_access      = true
  cluster_endpoint_public_access       = true
  cluster_endpoint_public_access_cidrs = [var.admin_cidr]

  # IRSA: creates the OIDC provider used by pod IAM roles.
  enable_irsa = true

  # Control plane logs -> CloudWatch Logs -> Wazuh (phase 5).
  cluster_enabled_log_types              = ["api", "audit", "authenticator"]
  cloudwatch_log_group_retention_in_days = 7

  # Envelope-encrypt Kubernetes secrets with a KMS key.
  create_kms_key = true
  cluster_encryption_config = {
    resources = ["secrets"]
  }
  kms_key_deletion_window_in_days = 7

  authentication_mode = "API"

  # Admins: whoever runs apply (local user or pipeline role), the pipeline apply
  # role (so the deploy workflow works either way) and any extra ARNs.
  # Built explicitly instead of enable_cluster_creator_admin_permissions to avoid
  # a duplicate entry when the creator is also in the list.
  enable_cluster_creator_admin_permissions = false
  access_entries = {
    for arn in local.cluster_admin_arns : replace(arn, "/[^a-zA-Z0-9]/", "-") => {
      principal_arn = arn
      policy_associations = {
        admin = {
          policy_arn   = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = { type = "cluster" }
        }
      }
    }
  }

  cluster_addons = {
    coredns    = {}
    kube-proxy = {}
    vpc-cni = {
      before_compute = true
      # Needed so NetworkPolicy (default-deny, phase 4) is enforced by the VPC CNI.
      configuration_values = jsonencode({
        enableNetworkPolicy = "true"
      })
    }
  }

  eks_managed_node_groups = {
    default = {
      # AL2023 kernel supports Falco's modern eBPF probe (no kernel module needed).
      ami_type = "AL2023_x86_64_STANDARD"

      # Required for cloudinit_post_nodeadm (below) to actually be merged into
      # the launch template's user data. Without this the module silently
      # drops it and only the default nodeadm bootstrap config is used --
      # found live: the Wazuh agent and Active Response script never installed.
      enable_bootstrap_user_data = true

      # cipherguard-* prefix so the pipeline apply role can manage it.
      iam_role_name            = "${local.name}-node"
      iam_role_use_name_prefix = true
      instance_types           = var.node_instance_types
      capacity_type            = "ON_DEMAND"

      min_size     = 1
      max_size     = 3
      desired_size = var.node_desired_size

      disk_size = 30

      # IMDSv2 only, hop limit 1: pods cannot reach node credentials (scenario D).
      metadata_options = {
        http_endpoint               = "enabled"
        http_tokens                 = "required"
        http_put_response_hop_limit = 1
      }

      labels = {
        workload = "lab"
      }

      # Wazuh agent on each node; it ships Falco's JSON events (phase 5).
      cloudinit_post_nodeadm = [{
        content_type = "text/x-shellscript; charset=\"us-ascii\""
        content = templatefile("${path.module}/templates/node-wazuh-agent.sh.tftpl", {
          manager_ip    = local.wazuh_private_ip
          agent_version = var.wazuh_agent_version
          ar_script     = file("${path.module}/../../detection/wazuh/active-response/cipherguard-isolate.sh")
        })
      }]
    }
  }
}
