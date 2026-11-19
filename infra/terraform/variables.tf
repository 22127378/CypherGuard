variable "region" {
  description = "AWS region for the lab."
  type        = string
  default     = "ap-southeast-1" # Singapore
}

variable "project" {
  description = "Name prefix for all resources."
  type        = string
  default     = "cipherguard"
}

variable "admin_cidr" {
  description = "Your public IP in CIDR form (x.x.x.x/32). Only this range can reach the EKS API endpoint."
  type        = string

  validation {
    condition     = can(cidrhost(var.admin_cidr, 0)) && endswith(var.admin_cidr, "/32")
    error_message = "admin_cidr must be a single /32 address, e.g. 203.0.113.10/32."
  }
}

variable "cluster_admin_arns" {
  description = "IAM user/role ARNs given cluster-admin access (e.g. your own IAM identity)."
  type        = list(string)
  default     = []
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "cluster_version" {
  description = "EKS Kubernetes version. Check supported versions before each session: aws eks describe-cluster-versions."
  type        = string
  default     = "1.33"
}

variable "node_instance_types" {
  description = "Worker node types. Sized for Falco + Kyverno + Wazuh agent + demo app."
  type        = list(string)
  default     = ["t3.large"]
}

variable "node_desired_size" {
  type    = number
  default = 2
}

variable "wazuh_instance_type" {
  description = "Wazuh all-in-one needs >= 8 GB RAM to run comfortably."
  type        = string
  default     = "t3.large"
}

variable "wazuh_version" {
  description = "Wazuh installer branch, e.g. 4.12 (https://packages.wazuh.com/<version>/wazuh-install.sh)."
  type        = string
  default     = "4.12"
}

variable "attacker_instance_type" {
  type    = string
  default = "t3.micro"
}

variable "attacker_port" {
  description = "Port the attacker host listens on for the simulated exfiltration."
  type        = number
  default     = 8080
}
