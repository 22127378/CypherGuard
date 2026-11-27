# An EC2 host reachable only through SSM Session Manager: its own instance role
# (SSM core attached), instance profile and the instance itself, with IMDSv2,
# an encrypted gp3 root volume and detailed monitoring. Used for the Wazuh
# manager and the attacker host; extra permissions are attached to `role_name`
# by the caller.

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = var.name
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "this" {
  name = var.name
  role = aws_iam_role.this.name
}

resource "aws_instance" "this" {
  #checkov:skip=CKV_AWS_88:Only the attacker host sets public_ip=true, to simulate an external host; no inbound from the internet (its SG allows only the node group)
  ami                         = var.ami
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  private_ip                  = var.private_ip
  associate_public_ip_address = var.public_ip
  vpc_security_group_ids      = var.security_group_ids
  iam_instance_profile        = aws_iam_instance_profile.this.name
  monitoring                  = true
  ebs_optimized               = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.volume_size
    encrypted   = true
  }

  user_data                   = var.user_data
  user_data_replace_on_change = true

  tags = { Name = var.name, Role = var.role }
}
