data "aws_caller_identity" "current" {}

# Created by infra/bootstrap; kept across lab sessions.
data "aws_ecr_repository" "demo_app" {
  name = "${local.name}/demo-app"
}

# IRSA role for the demo app. Deliberately narrow: it may read only its own SSM
# parameters, so the escalation step (3) and scenario I produce AccessDenied
# events in CloudTrail when the attacker tries S3 or IAM calls.
module "demo_app_irsa" {
  #checkov:skip=CKV_TF_1:Registry module pinned by version constraint; Dependabot tracks updates
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 6.11"

  role_name = "${local.name}-demo-app"

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["demo:demo-app"]
    }
  }

  role_policy_arns = {
    demo = aws_iam_policy.demo_app.arn
  }
}

data "aws_iam_policy_document" "demo_app" {
  statement {
    sid       = "ReadOwnConfig"
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.name}/demo-app/*"]
  }
}

resource "aws_iam_policy" "demo_app" {
  name   = "${local.name}-demo-app"
  policy = data.aws_iam_policy_document.demo_app.json
}

resource "aws_ssm_parameter" "demo_app_greeting" {
  #checkov:skip=CKV_AWS_337:Non-sensitive demo value; aws/ssm managed key is enough
  name  = "/${local.name}/demo-app/greeting"
  type  = "SecureString" # aws/ssm key; decrypt allowed via SSM for account principals
  value = "hello from CipherGuard"
}

# Kyverno verifies Cosign signatures stored in ECR. Pods cannot reach IMDS
# (hop limit 1), so the admission controller gets its own read-only ECR role.
module "kyverno_irsa" {
  #checkov:skip=CKV_TF_1:Registry module pinned by version constraint; Dependabot tracks updates
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 6.11"

  role_name = "${local.name}-kyverno"

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kyverno:kyverno-admission-controller"]
    }
  }

  role_policy_arns = {
    ecr = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  }
}
