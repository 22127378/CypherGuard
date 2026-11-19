# GitHub Actions -> AWS via OIDC. No access keys anywhere.
#
# Roles and who can assume them (token "sub" claim):
#   gha-plan      pull requests and main        read-only + state lock
#   gha-apply     environment "lab" only         create/destroy the lab (needs manual approval)
#   gha-ecr-push  main branch only               push/sign the demo image

variable "github_repo" {
  description = "owner/repo allowed to assume the pipeline roles."
  type        = string
  default     = "22127378/CypherGuard"
}

locals {
  gh_sub_prefix = "repo:${var.github_repo}"
  account_id    = data.aws_caller_identity.current.account_id
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # AWS no longer validates these for GitHub, but older providers require a value.
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}

data "aws_iam_policy_document" "gh_trust" {
  for_each = {
    plan     = ["${local.gh_sub_prefix}:pull_request", "${local.gh_sub_prefix}:ref:refs/heads/main"]
    apply    = ["${local.gh_sub_prefix}:environment:lab"]
    ecr_push = ["${local.gh_sub_prefix}:ref:refs/heads/main"]
  }

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = each.value
    }
  }
}

# ---------- State access shared by plan and apply ----------

data "aws_iam_policy_document" "tf_state" {
  statement {
    sid       = "StateBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn]
  }
  statement {
    sid       = "StateObjects"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/lab/*"]
  }
  statement {
    sid       = "StateLock"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:DescribeTable"]
    resources = [aws_dynamodb_table.lock.arn]
  }
}

resource "aws_iam_policy" "tf_state" {
  name   = "${var.project}-gha-tfstate"
  policy = data.aws_iam_policy_document.tf_state.json
}

# ---------- Plan role ----------

resource "aws_iam_role" "gha_plan" {
  name                 = "${var.project}-gha-plan"
  assume_role_policy   = data.aws_iam_policy_document.gh_trust["plan"].json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "gha_plan_readonly" {
  role       = aws_iam_role.gha_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "gha_plan_state" {
  role       = aws_iam_role.gha_plan.name
  policy_arn = aws_iam_policy.tf_state.arn
}

# ---------- Apply role ----------
# PowerUserAccess covers EC2/EKS/VPC/KMS/Logs/SSM. IAM is limited to resources
# named cipherguard-* plus the EKS OIDC provider.

resource "aws_iam_role" "gha_apply" {
  name                 = "${var.project}-gha-apply"
  assume_role_policy   = data.aws_iam_policy_document.gh_trust["apply"].json
  max_session_duration = 7200 # EKS create/destroy can take > 1 h end to end
}

resource "aws_iam_role_policy_attachment" "gha_apply_poweruser" {
  role       = aws_iam_role.gha_apply.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_iam_role_policy_attachment" "gha_apply_state" {
  role       = aws_iam_role.gha_apply.name
  policy_arn = aws_iam_policy.tf_state.arn
}

data "aws_iam_policy_document" "gha_apply_iam" {
  statement {
    sid = "ManageLabIam"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:UpdateRole", "iam:UpdateAssumeRolePolicy",
      "iam:TagRole", "iam:UntagRole", "iam:PassRole",
      "iam:AttachRolePolicy", "iam:DetachRolePolicy",
      "iam:PutRolePolicy", "iam:DeleteRolePolicy",
      "iam:CreatePolicy", "iam:DeletePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicyVersion",
      "iam:TagPolicy", "iam:UntagPolicy",
      "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile",
      "iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile",
      "iam:TagInstanceProfile", "iam:UntagInstanceProfile",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:role/${var.project}-*",
      "arn:aws:iam::${local.account_id}:policy/${var.project}-*",
      "arn:aws:iam::${local.account_id}:instance-profile/${var.project}-*",
    ]
  }

  statement {
    sid = "ManageEksOidcProvider"
    actions = [
      "iam:CreateOpenIDConnectProvider", "iam:DeleteOpenIDConnectProvider",
      "iam:TagOpenIDConnectProvider", "iam:UntagOpenIDConnectProvider",
      "iam:UpdateOpenIDConnectProviderThumbprint",
    ]
    resources = ["arn:aws:iam::${local.account_id}:oidc-provider/oidc.eks.${var.region}.amazonaws.com/*"]
  }

  statement {
    sid       = "ServiceLinkedRoles"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]
  }

  # The pipeline must never modify its own roles.
  statement {
    sid     = "ProtectPipelineRoles"
    effect  = "Deny"
    actions = ["iam:*"]
    resources = [
      "arn:aws:iam::${local.account_id}:role/${var.project}-gha-*",
      "arn:aws:iam::${local.account_id}:policy/${var.project}-gha-*",
    ]
  }

  # Block the obvious escalation path: attaching admin policies to lab roles.
  statement {
    sid       = "NoAdminPolicies"
    effect    = "Deny"
    actions   = ["iam:AttachRolePolicy"]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "iam:PolicyARN"
      values = [
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
      ]
    }
  }
}

resource "aws_iam_role_policy" "gha_apply_iam" {
  name   = "lab-iam"
  role   = aws_iam_role.gha_apply.id
  policy = data.aws_iam_policy_document.gha_apply_iam.json
}

# ---------- ECR push role ----------

resource "aws_iam_role" "gha_ecr_push" {
  name                 = "${var.project}-gha-ecr-push"
  assume_role_policy   = data.aws_iam_policy_document.gh_trust["ecr_push"].json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "gha_ecr_push" {
  statement {
    sid       = "EcrLogin"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid = "PushDemoApp"
    actions = [
      "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload",
      "ecr:PutImage", "ecr:DescribeImages", "ecr:DescribeImageScanFindings",
    ]
    resources = [aws_ecr_repository.demo_app.arn]
  }
}

resource "aws_iam_role_policy" "gha_ecr_push" {
  name   = "ecr-push"
  role   = aws_iam_role.gha_ecr_push.id
  policy = data.aws_iam_policy_document.gha_ecr_push.json
}

# ---------- Values to copy into GitHub repository variables ----------

output "github_repository_variables" {
  description = "Set these under Settings > Secrets and variables > Actions > Variables."
  value = {
    AWS_PLAN_ROLE_ARN     = aws_iam_role.gha_plan.arn
    AWS_APPLY_ROLE_ARN    = aws_iam_role.gha_apply.arn
    AWS_ECR_PUSH_ROLE_ARN = aws_iam_role.gha_ecr_push.arn
    TF_STATE_BUCKET       = aws_s3_bucket.state.id
    TF_LOCK_TABLE         = aws_dynamodb_table.lock.name
    ECR_REPOSITORY        = aws_ecr_repository.demo_app.name
  }
}
