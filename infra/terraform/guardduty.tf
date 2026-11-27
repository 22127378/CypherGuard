# Cloud telemetry and response (completes the architecture's bottom row):
#   GuardDuty findings -> EventBridge -> CloudWatch Logs -> Wazuh (detection)
#                                     -> Lambda auto-fix   (contain the credential)
#
# One detector per region per account; set enable_guardduty = false if the
# account already has one.

# ---------- Detector ----------

resource "aws_guardduty_detector" "lab" {
  #checkov:skip=CKV2_AWS_3:This resource is exactly how GuardDuty is enabled for the lab region
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  datasources {
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }
}

# ---------- Findings -> CloudWatch Logs (for Wazuh) ----------

resource "aws_cloudwatch_log_group" "guardduty" {
  count             = var.enable_guardduty ? 1 : 0
  name              = "/${local.name}/guardduty"
  retention_in_days = 7
  #checkov:skip=CKV_AWS_158:SSE by the CloudWatch default key is enough for short-lived lab findings
  #checkov:skip=CKV_AWS_338:Lab logs are destroyed each session; 7 days is intentional
}

data "aws_iam_policy_document" "guardduty_logs" {
  count = var.enable_guardduty ? 1 : 0
  statement {
    sid       = "EventBridgeToLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.guardduty[0].arn}:*"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "guardduty" {
  count           = var.enable_guardduty ? 1 : 0
  policy_name     = "${local.name}-guardduty-logs"
  policy_document = data.aws_iam_policy_document.guardduty_logs[0].json
}

resource "aws_cloudwatch_event_rule" "guardduty_all" {
  count       = var.enable_guardduty ? 1 : 0
  name        = "${local.name}-guardduty-all"
  description = "All GuardDuty findings to CloudWatch Logs for Wazuh"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_logs" {
  count     = var.enable_guardduty ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty_all[0].name
  arn       = aws_cloudwatch_log_group.guardduty[0].arn
  target_id = "cw-logs"
}

# ---------- High-severity findings -> Lambda auto-fix ----------

data "archive_file" "autofix" {
  count       = var.enable_guardduty ? 1 : 0
  type        = "zip"
  source_file = "${path.module}/lambda/autofix.py"
  output_path = "${path.module}/lambda/autofix.zip"
}

data "aws_iam_policy_document" "autofix_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "autofix" {
  count              = var.enable_guardduty ? 1 : 0
  name               = "${local.name}-autofix"
  assume_role_policy = data.aws_iam_policy_document.autofix_assume.json
}

data "aws_iam_policy_document" "autofix" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"]
  }

  # Quarantine only in-scope lab roles.
  statement {
    sid       = "QuarantineLabRoles"
    actions   = ["iam:PutRolePolicy", "iam:DeleteRolePolicy"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name}-*"]
  }

  # Never the pipeline roles or its own role, even if the code is wrong.
  statement {
    sid     = "ProtectCriticalRoles"
    effect  = "Deny"
    actions = ["iam:PutRolePolicy", "iam:DeleteRolePolicy"]
    resources = [
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name}-gha-*",
      "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name}-autofix",
    ]
  }

  statement {
    sid       = "DeactivateLeakedKeys"
    actions   = ["iam:UpdateAccessKey"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
  }
}

resource "aws_iam_role_policy" "autofix" {
  count  = var.enable_guardduty ? 1 : 0
  name   = "autofix"
  role   = aws_iam_role.autofix[0].id
  policy = data.aws_iam_policy_document.autofix.json
}

resource "aws_lambda_function" "autofix" {
  #checkov:skip=CKV_AWS_272:Lab function; code signing adds ops overhead with no extra control here
  #checkov:skip=CKV_AWS_116:No DLQ; a failed auto-fix is surfaced in logs and the GuardDuty finding persists
  #checkov:skip=CKV_AWS_117:No VPC needed; it calls IAM, a global endpoint
  #checkov:skip=CKV_AWS_173:Env vars hold no secrets
  #checkov:skip=CKV_AWS_50:X-Ray not needed for a lab
  #checkov:skip=CKV_AWS_115:Reserving concurrency is rejected on accounts with a low unreserved pool (found live)
  # No reserved_concurrent_executions: some accounts have a low (e.g. 10) total
  # unreserved concurrency pool, and reserving any of it there is rejected.
  # GuardDuty invokes this rarely, so an unreserved default is fine for a lab.
  count            = var.enable_guardduty ? 1 : 0
  function_name    = "${local.name}-autofix"
  role             = aws_iam_role.autofix[0].arn
  runtime          = "python3.13"
  handler          = "autofix.handler"
  filename         = data.archive_file.autofix[0].output_path
  source_code_hash = data.archive_file.autofix[0].output_base64sha256
  timeout          = 30

  environment {
    variables = {
      # Set to "1" to log intended actions without changing anything.
      CG_DRYRUN = var.autofix_dry_run ? "1" : "0"
    }
  }
}

resource "aws_cloudwatch_log_group" "autofix" {
  count             = var.enable_guardduty ? 1 : 0
  name              = "/aws/lambda/${local.name}-autofix"
  retention_in_days = 7
  #checkov:skip=CKV_AWS_158:Default CloudWatch encryption is enough for lab logs
  #checkov:skip=CKV_AWS_338:Lab logs are destroyed each session; 7 days is intentional
}

resource "aws_cloudwatch_event_rule" "guardduty_high" {
  count       = var.enable_guardduty ? 1 : 0
  name        = "${local.name}-guardduty-high"
  description = "High-severity GuardDuty findings to the auto-fix Lambda"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_lambda" {
  count     = var.enable_guardduty ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty_high[0].name
  arn       = aws_lambda_function.autofix[0].arn
  target_id = "autofix"
}

resource "aws_lambda_permission" "guardduty" {
  count         = var.enable_guardduty ? 1 : 0
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.autofix[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_high[0].arn
}

output "guardduty_log_group" {
  value = var.enable_guardduty ? aws_cloudwatch_log_group.guardduty[0].name : ""
}

output "autofix_function" {
  value = var.enable_guardduty ? aws_lambda_function.autofix[0].function_name : ""
}
