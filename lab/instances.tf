locals {
  # One instance per case the exposure check has to get right. In the clean lab every instance
  # uses the restricted group instead.
  scenarios = {
    open-ssh      = { subnet = "open", public_ip = true, group = "ssh" }
    nacl-deny     = { subnet = "denyssh", public_ip = true, group = "ssh" }
    nacl-noreturn = { subnet = "noreturn", public_ip = true, group = "ssh" }
    no-route      = { subnet = "noroute", public_ip = true, group = "ssh" }
    private       = { subnet = "private", public_ip = false, group = "ssh" }
    open-rdp      = { subnet = "open", public_ip = true, group = "rdp" }
    restricted    = { subnet = "open", public_ip = true, group = "restricted" }
    all-open      = { subnet = "open", public_ip = true, group = "all" }
  }

  world_group_ids = { for name, group in aws_security_group.world : name => group.id }
  ami             = coalesce(var.ami_id, one(data.aws_ssm_parameter.al2023[*].insecure_value))
}

data "aws_ssm_parameter" "al2023" {
  count = var.ami_id == null ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

resource "aws_security_group" "restricted" {
  name        = "cloudsentry-restricted"
  description = "SSH from one documentation address only"
  vpc_id      = aws_vpc.a.id

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["198.51.100.7/32"]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "cloudsentry-restricted" }
}

resource "aws_instance" "scenario" {
  for_each                    = local.scenarios
  ami                         = local.ami
  instance_type               = "t4g.micro"
  subnet_id                   = aws_subnet.a[each.value.subnet].id
  associate_public_ip_address = each.value.public_ip
  vpc_security_group_ids      = [lookup(local.world_group_ids, each.value.group, aws_security_group.restricted.id)]
  user_data                   = file("${path.module}/listener.sh")

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = var.faults && each.key == "restricted" ? "optional" : "required"
  }

  tags = merge(
    { Name = "cloudsentry-${each.key}" },
    var.faults && each.key == "restricted" ? { Fault = "CIS 5.7" } : {},
  )
}
