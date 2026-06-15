resource "aws_instance" "aggregator" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  user_data = file("${path.module}/user_data.sh")

  vpc_security_group_ids = [
    aws_security_group.UniVulner_Sec_Group.id
  ]

  associate_public_ip_address = true
  disable_api_termination = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    delete_on_termination = false
  }

  tags = {
    Name = var.instance_name
  }
}