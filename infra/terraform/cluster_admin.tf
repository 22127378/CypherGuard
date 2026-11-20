# A cluster-admin IAM role that any principal in this account can assume. EKS
# access entries cannot be created for the root user, so when the deploying
# identity is root (or otherwise cannot be an access entry) kubectl assumes this
# role instead. The kubeconfig command wires it in with --role-arn.

data "aws_iam_policy_document" "cluster_admin_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "cluster_admin" {
  name               = "${local.name}-cluster-admin"
  assume_role_policy = data.aws_iam_policy_document.cluster_admin_assume.json
}
