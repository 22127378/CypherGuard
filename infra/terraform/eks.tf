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

  authentication_mode                      = "API"
  enable_cluster_creator_admin_permissions = true

  # Extra cluster admins (your IAM user/role), so kubectl works whether the lab
  # was created locally or by the pipeline role.
  access_entries = {
    for i, arn in var.cluster_admin_arns : "admin-${i}" => {
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
    }
  }
}
