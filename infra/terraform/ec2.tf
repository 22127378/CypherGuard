data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

# ---------- Wazuh server ----------

data "aws_iam_policy_document" "wazuh" {
  # Store the generated admin password in SSM instead of on disk only.
  statement {
    sid       = "StoreAdminPassword"
    actions   = ["ssm:PutParameter"]
    resources = ["arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.name}/wazuh/*"]
  }

  # Read EKS control-plane logs from CloudWatch Logs (phase 5).
  statement {
    sid       = "ListLogGroups"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }

  statement {
    sid = "ReadEksLogs"
    actions = [
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:GetLogEvents",
      "logs:FilterLogEvents",
    ]
    resources = [
      module.eks.cloudwatch_log_group_arn,
      "${module.eks.cloudwatch_log_group_arn}:*",
    ]
  }

  # GuardDuty findings arrive in their own log group (EventBridge target).
  # Found live: without this, Wazuh's DescribeLogStreams on it was denied
  # every poll and no GuardDuty finding ever reached Wazuh.
  dynamic "statement" {
    for_each = var.enable_guardduty ? [1] : []
    content {
      sid = "ReadGuardDutyLogs"
      actions = [
        "logs:DescribeLogStreams",
        "logs:GetLogEvents",
        "logs:FilterLogEvents",
      ]
      resources = [
        aws_cloudwatch_log_group.guardduty[0].arn,
        "${aws_cloudwatch_log_group.guardduty[0].arn}:*",
      ]
    }
  }

  # Read CloudTrail logs from S3 (phase 5).
  dynamic "statement" {
    for_each = var.enable_cloudtrail ? [1] : []
    content {
      sid       = "ReadCloudTrailBucket"
      actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
      resources = [aws_s3_bucket.cloudtrail[0].arn]
    }
  }

  dynamic "statement" {
    for_each = var.enable_cloudtrail ? [1] : []
    content {
      sid       = "ReadCloudTrailObjects"
      actions   = ["s3:GetObject"]
      resources = ["${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/*"]
    }
  }
}

resource "aws_iam_role_policy" "wazuh" {
  name   = "wazuh"
  role   = module.wazuh.role_name
  policy = data.aws_iam_policy_document.wazuh.json
}

# Fixed private IP, computed from the VPC CIDR so it is known at plan time.
# The node user data embeds it; with an IP only known after apply, the EKS
# module cannot size its cloud-init parts and a from-scratch apply fails
# ("Invalid count argument"), found on the first fresh deploy.
locals {
  wazuh_private_ip = cidrhost(cidrsubnet(var.vpc_cidr, 4, 0), 10)
}

module "wazuh" {
  source = "./modules/ssm-host"

  name               = "${local.name}-wazuh"
  role               = "siem"
  ami                = data.aws_ami.ubuntu.id
  instance_type      = var.wazuh_instance_type
  subnet_id          = module.vpc.private_subnets[0]
  private_ip         = local.wazuh_private_ip
  security_group_ids = [aws_security_group.wazuh.id]
  volume_size        = 50
  user_data = templatefile("${path.module}/templates/wazuh-userdata.sh.tftpl", {
    wazuh_version = var.wazuh_version
    region        = var.region
    param_name    = "/${local.name}/wazuh/admin-password"
  })

  # Wait for the NAT Gateway so the installer can download packages.
  depends_on = [module.vpc]
}

# ---------- Attacker host ----------

module "attacker" {
  source = "./modules/ssm-host"

  name               = "${local.name}-attacker"
  role               = "attacker-sim"
  ami                = data.aws_ami.al2023.id
  instance_type      = var.attacker_instance_type
  subnet_id          = module.vpc.public_subnets[0]
  public_ip          = true # simulates an external host
  security_group_ids = [aws_security_group.attacker.id]
  volume_size        = 8
  user_data = templatefile("${path.module}/templates/attacker-userdata.sh.tftpl", {
    port            = var.attacker_port
    receiver_script = file("${path.module}/../../attack/receiver/receiver.py")
  })
}

# Resources moved into modules/ssm-host; keeps an existing lab from being
# destroyed and recreated by the refactor.
moved {
  from = aws_iam_role.wazuh
  to   = module.wazuh.aws_iam_role.this
}
moved {
  from = aws_iam_role_policy_attachment.wazuh_ssm
  to   = module.wazuh.aws_iam_role_policy_attachment.ssm
}
moved {
  from = aws_iam_instance_profile.wazuh
  to   = module.wazuh.aws_iam_instance_profile.this
}
moved {
  from = aws_instance.wazuh
  to   = module.wazuh.aws_instance.this
}
moved {
  from = aws_iam_role.attacker
  to   = module.attacker.aws_iam_role.this
}
moved {
  from = aws_iam_role_policy_attachment.attacker_ssm
  to   = module.attacker.aws_iam_role_policy_attachment.ssm
}
moved {
  from = aws_iam_instance_profile.attacker
  to   = module.attacker.aws_iam_instance_profile.this
}
moved {
  from = aws_instance.attacker
  to   = module.attacker.aws_instance.this
}
