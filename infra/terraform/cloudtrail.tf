# CloudTrail for the lab account: Wazuh reads it from S3 to catch AccessDenied
# calls by the demo pod role (step 3, scenario I) and node credentials used
# from outside the NAT Gateway (scenario D).
#
# The first trail with management events is free. If the account already has
# a trail (e.g. an organization trail), set enable_cloudtrail = false.

locals {
  cloudtrail_bucket = "${local.name}-cloudtrail-${data.aws_caller_identity.current.account_id}"
  cloudtrail_arn    = "arn:aws:cloudtrail:${var.region}:${data.aws_caller_identity.current.account_id}:trail/${local.name}"
}

resource "aws_s3_bucket" "cloudtrail" {
  #checkov:skip=CKV_AWS_18:Access logging needs another bucket; lab trail bucket is destroyed every session
  #checkov:skip=CKV_AWS_144:No cross-region replication for short-lived lab logs
  #checkov:skip=CKV_AWS_145:SSE-S3 is sufficient for lab CloudTrail logs
  #checkov:skip=CKV_AWS_21:Versioning is unnecessary for logs expired after 7 days
  #checkov:skip=CKV2_AWS_62:Wazuh polls the bucket; no event notifications needed
  count         = var.enable_cloudtrail ? 1 : 0
  bucket        = local.cloudtrail_bucket
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count                   = var.enable_cloudtrail ? 1 : 0
  bucket                  = aws_s3_bucket.cloudtrail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  rule {
    id     = "expire-lab-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "cloudtrail_bucket" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail[0].arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.cloudtrail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.cloudtrail_arn]
    }
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.cloudtrail[0].arn,
      "${aws_s3_bucket.cloudtrail[0].arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id
  policy = data.aws_iam_policy_document.cloudtrail_bucket[0].json
}

resource "aws_cloudtrail" "lab" {
  #checkov:skip=CKV_AWS_35:SSE-S3 on the bucket is sufficient for lab logs; a CMK adds cost
  #checkov:skip=CKV_AWS_252:No SNS consumer; Wazuh polls S3
  #checkov:skip=CKV2_AWS_10:CloudWatch delivery is not needed; Wazuh reads S3 directly
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = local.name
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
