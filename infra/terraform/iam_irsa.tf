data "aws_caller_identity" "current" {}

# IRSA role for the demo app. Deliberately narrow: it may read only its own SSM
# parameters, so the escalation step (3) and scenario I produce AccessDenied
# events in CloudTrail when the attacker tries S3 or IAM calls.
module "demo_app_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.48"

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
  name  = "/${local.name}/demo-app/greeting"
  type  = "String"
  value = "hello from CipherGuard"
}
