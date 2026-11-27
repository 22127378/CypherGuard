locals {
  azs  = var.azs
  name = var.project
}

module "vpc" {
  #checkov:skip=CKV_TF_1:Registry module pinned by version constraint; Dependabot tracks updates
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.8"

  name = "${local.name}-vpc"
  cidr = var.vpc_cidr
  azs  = local.azs

  private_subnets = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  public_subnets  = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 8, 48 + i)]

  # One NAT Gateway keeps cost down; acceptable for a lab.
  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  # Lock down the default security group (Checkov CKV2_AWS_12).
  manage_default_security_group  = true
  default_security_group_ingress = []
  default_security_group_egress  = []

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
}
