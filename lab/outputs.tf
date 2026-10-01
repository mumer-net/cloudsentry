output "vpcs" {
  value = { a = aws_vpc.a.id, b = aws_vpc.b.id }
}

output "instances" {
  value = { for name, i in aws_instance.scenario : name => { id = i.id, public_ip = i.public_ip } }
}
