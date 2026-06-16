resource "aws_key_pair" "univulner_key" {
  key_name   = "univulner-key"
  public_key = file(var.public_key_path)
}

resource "aws_instance" "aggregator" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  key_name = aws_key_pair.univulner_key.key_name

  vpc_security_group_ids = [
    aws_security_group.UniVulner_Sec_Group.id
  ]
  
  user_data = file("${path.module}/user_data.sh")

  disable_api_termination = true
  
  associate_public_ip_address = true

  root_block_device {
    volume_size = var.root_volume_size
    volume_type = "gp3"
    delete_on_termination = false
  }

  tags = {
    Name = var.instance_name
  }
}