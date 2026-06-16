resource "tls_private_key" "ssh" {
  algorithm = "ED25519"
}

resource "aws_key_pair" "univulner" {
  key_name   = "univulner-key"
  public_key = tls_private_key.ssh.public_key_openssh
}

resource "local_file" "private_key" {
  filename        = var.private_key_path
  content         = tls_private_key.ssh.private_key_openssh
  file_permission = "0600"
}

resource "aws_instance" "aggregator" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  key_name      = aws_key_pair.univulner.key_name

  vpc_security_group_ids = [
    aws_security_group.UniVulner_Sec_Group.id
  ]

  user_data = file("${path.module}/user_data.sh")

  user_data_replace_on_change = true

  disable_api_termination = true

  associate_public_ip_address = true

  root_block_device {
    volume_size           = var.root_volume_size
    volume_type           = "gp3"
    delete_on_termination = false
  }

  tags = {
    Name = var.instance_name
  }

  metadata_options {
    http_tokens = "required"
  }
}