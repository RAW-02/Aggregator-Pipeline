output "instance_id" {
  value = aws_instance.aggregator.id
}

output "public_ip" {
  value = aws_instance.aggregator.public_ip
}

output "public_dns" {
  value = aws_instance.aggregator.public_dns
}