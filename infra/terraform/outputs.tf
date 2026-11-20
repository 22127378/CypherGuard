output "region" {
  value = var.region
}

output "cluster_name" {
  value = module.eks.cluster_name
}

output "cluster_admin_role_arn" {
  description = "Assume this role for kubectl access (used by kubeconfig_command)."
  value       = aws_iam_role.cluster_admin.arn
}

output "kubeconfig_command" {
  value = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name} --role-arn ${aws_iam_role.cluster_admin.arn}"
}

output "ecr_repository_url" {
  value = data.aws_ecr_repository.demo_app.repository_url
}

output "demo_app_role_arn" {
  description = "Annotate the demo-app ServiceAccount with eks.amazonaws.com/role-arn = this value."
  value       = module.demo_app_irsa.iam_role_arn
}

output "wazuh_instance_id" {
  value = aws_instance.wazuh.id
}

output "wazuh_private_ip" {
  value = aws_instance.wazuh.private_ip
}

output "wazuh_dashboard_tunnel" {
  description = "Open https://localhost:8443 after running this."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.wazuh.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=443,localPortNumber=8443"
}

output "wazuh_admin_password_command" {
  value = "aws ssm get-parameter --region ${var.region} --with-decryption --name /${local.name}/wazuh/admin-password --query Parameter.Value --output text"
}

output "attacker_instance_id" {
  value = aws_instance.attacker.id
}

output "attacker_private_ip" {
  description = "Exfil target used by the attack scripts (reached from pods inside the VPC)."
  value       = aws_instance.attacker.private_ip
}

output "eks_audit_log_group" {
  value = module.eks.cloudwatch_log_group_name
}

output "kyverno_role_arn" {
  value = module.kyverno_irsa.iam_role_arn
}
