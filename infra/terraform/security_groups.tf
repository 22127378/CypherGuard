# Wazuh and attacker hosts have no SSH and no inbound from the internet.
# Admin access is through SSM Session Manager (shell and port forwarding for the
# Wazuh dashboard), which is stricter than the proposal's "443 from your IP".

resource "aws_security_group" "wazuh" {
  name        = "${local.name}-wazuh"
  description = "Wazuh all-in-one server"
  vpc_id      = module.vpc.vpc_id

  tags = { Name = "${local.name}-wazuh" }
}

resource "aws_vpc_security_group_ingress_rule" "wazuh_agent_events" {
  security_group_id            = aws_security_group.wazuh.id
  description                  = "Wazuh agent events from EKS worker nodes"
  referenced_security_group_id = module.eks.node_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 1514
  to_port                      = 1514
}

resource "aws_vpc_security_group_ingress_rule" "wazuh_agent_enrolment" {
  security_group_id            = aws_security_group.wazuh.id
  description                  = "Wazuh agent enrolment from EKS worker nodes"
  referenced_security_group_id = module.eks.node_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 1515
  to_port                      = 1515
}

resource "aws_vpc_security_group_egress_rule" "wazuh_https" {
  security_group_id = aws_security_group.wazuh.id
  description       = "AWS APIs (CloudWatch Logs, SSM) and package repositories"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "wazuh_http" {
  security_group_id = aws_security_group.wazuh.id
  description       = "Package repositories (apt over HTTP)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_security_group" "attacker" {
  name        = "${local.name}-attacker"
  description = "Simulated attacker host that receives synthetic exfiltration data"
  vpc_id      = module.vpc.vpc_id

  tags = { Name = "${local.name}-attacker" }
}

resource "aws_vpc_security_group_ingress_rule" "attacker_receiver" {
  security_group_id            = aws_security_group.attacker.id
  description                  = "Exfil receiver, reachable only from EKS worker nodes"
  referenced_security_group_id = module.eks.node_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = var.attacker_port
  to_port                      = var.attacker_port
}

resource "aws_vpc_security_group_egress_rule" "attacker_https" {
  security_group_id = aws_security_group.attacker.id
  description       = "SSM and package updates"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "attacker_http" {
  security_group_id = aws_security_group.attacker.id
  description       = "Package updates (dnf over HTTP)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}
