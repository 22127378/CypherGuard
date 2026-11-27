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

# ---------- Shared SSM instance role ----------

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# ---------- Wazuh server ----------

resource "aws_iam_role" "wazuh" {
  name               = "${local.name}-wazuh"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "wazuh_ssm" {
  role       = aws_iam_role.wazuh.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

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
  role   = aws_iam_role.wazuh.id
  policy = data.aws_iam_policy_document.wazuh.json
}

resource "aws_iam_instance_profile" "wazuh" {
  name = "${local.name}-wazuh"
  role = aws_iam_role.wazuh.name
}

# Fixed private IP, computed from the VPC CIDR so it is known at plan time.
# The node user data embeds it; with an IP only known after apply, the EKS
# module cannot size its cloud-init parts and a from-scratch apply fails
# ("Invalid count argument"), found on the first fresh deploy.
locals {
  wazuh_private_ip = cidrhost(cidrsubnet(var.vpc_cidr, 4, 0), 10)
}

resource "aws_instance" "wazuh" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.wazuh_instance_type
  subnet_id              = module.vpc.private_subnets[0]
  private_ip             = local.wazuh_private_ip
  vpc_security_group_ids = [aws_security_group.wazuh.id]
  iam_instance_profile   = aws_iam_instance_profile.wazuh.name
  monitoring             = true
  ebs_optimized          = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 50
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/wazuh-userdata.sh.tftpl", {
    wazuh_version = var.wazuh_version
    region        = var.region
    param_name    = "/${local.name}/wazuh/admin-password"
  })
  user_data_replace_on_change = true

  # Wait for the NAT Gateway so the installer can download packages.
  depends_on = [module.vpc]

  tags = { Name = "${local.name}-wazuh", Role = "siem" }
}

# ---------- Attacker host ----------

resource "aws_iam_role" "attacker" {
  name               = "${local.name}-attacker"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "attacker_ssm" {
  role       = aws_iam_role.attacker.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "attacker" {
  name = "${local.name}-attacker"
  role = aws_iam_role.attacker.name
}

resource "aws_instance" "attacker" {
  #checkov:skip=CKV_AWS_88:Intentional: simulates an external host; no inbound from the internet (SG allows only the node group)
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.attacker_instance_type
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.attacker.id]
  iam_instance_profile        = aws_iam_instance_profile.attacker.name
  monitoring                  = true
  ebs_optimized               = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/attacker-userdata.sh.tftpl", {
    port            = var.attacker_port
    receiver_script = file("${path.module}/../../attack/receiver/receiver.py")
  })
  user_data_replace_on_change = true

  tags = { Name = "${local.name}-attacker", Role = "attacker-sim" }
}
