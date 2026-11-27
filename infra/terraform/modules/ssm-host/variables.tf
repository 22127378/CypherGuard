variable "name" {
  description = "Name of the instance, its IAM role and instance profile"
  type        = string
}

variable "role" {
  description = "Value of the Role tag (what the host is for)"
  type        = string
}

variable "ami" {
  type = string
}

variable "instance_type" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "private_ip" {
  description = "Fixed private IP, or null to let AWS pick one"
  type        = string
  default     = null
}

variable "public_ip" {
  description = "Associate a public IP (only for a host that simulates something outside the VPC)"
  type        = bool
  default     = false
}

variable "security_group_ids" {
  type = list(string)
}

variable "volume_size" {
  description = "Root volume size in GiB"
  type        = number
}

variable "user_data" {
  type = string
}
