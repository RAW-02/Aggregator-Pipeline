variable "aws_region" {
  default = "ap-south-1"
}

variable "instance_type" {
  default = "m7i-flex.large"
}

variable "instance_name" {
  default = "Aggregator-UniVulner"
}

variable "root_volume_size" {
  default = 30
}

variable "private_key_path" {
  description = "Location where Terraform stores the generated SSH private key"
  type        = string
  default     = "C:/Users/Shree/.ssh/univulner.pem"
}