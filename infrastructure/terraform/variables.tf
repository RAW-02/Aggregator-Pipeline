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

variable "public_key_path" {
  default = "~/.ssh/id_rsa.pub"
}