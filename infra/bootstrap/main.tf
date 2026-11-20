# One-time bootstrap: S3 bucket + DynamoDB table for the lab's remote state.
# Uses local state on purpose and is NOT destroyed with the lab.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

variable "region" {
  type    = string
  default = "ap-southeast-1"
}

variable "project" {
  type    = string
  default = "cipherguard"
}

variable "budget_alert_email" {
  description = "Email for AWS Budgets alerts. Empty = no budget created."
  type        = string
  default     = ""
}

variable "monthly_budget_usd" {
  type    = number
  default = 50
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "CipherGuard"
      Component = "tfstate"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  bucket_name = "${var.project}-tfstate-${data.aws_caller_identity.current.account_id}"
  lock_table  = "${var.project}-tflock"
}

resource "aws_s3_bucket" "state" {
  #checkov:skip=CKV_AWS_18:Access logging needs a second bucket; CloudTrail data events cover this in phase 5
  #checkov:skip=CKV_AWS_144:Cross-region replication is not needed for lab state (versioning enabled)
  #checkov:skip=CKV_AWS_145:SSE-S3 is sufficient for lab state; a CMK adds cost with no extra control here
  #checkov:skip=CKV2_AWS_62:No consumer for event notifications on the state bucket
  bucket = local.bucket_name

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "expire-old-state-versions"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Deny non-TLS access to the state bucket.
resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_dynamodb_table" "lock" {
  #checkov:skip=CKV_AWS_119:Lock table holds no data; AWS-owned key encryption is enough
  name         = local.lock_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

# Writes the backend config consumed by infra/terraform (terraform init -backend-config=backend.hcl).
resource "local_file" "backend_hcl" {
  filename = "${path.module}/../terraform/backend.hcl"
  content  = <<-EOT
    bucket         = "${aws_s3_bucket.state.id}"
    key            = "lab/terraform.tfstate"
    region         = "${var.region}"
    dynamodb_table = "${aws_dynamodb_table.lock.name}"
    encrypt        = true
  EOT
}

# Budget lives here (persistent), not in the lab stack, so it survives each destroy.
# Account-wide filter: the lab is the main workload in this account.
resource "aws_budgets_budget" "lab" {
  count        = var.budget_alert_email == "" ? 0 : 1
  name         = "${var.project}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_alert_email]
  }
}

output "state_bucket" {
  value = aws_s3_bucket.state.id
}

output "lock_table" {
  value = aws_dynamodb_table.lock.name
}
