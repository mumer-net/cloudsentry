# Everything in this file exists only when faults = true. Each resource that breaks a CIS control
# carries a Fault tag naming it, which is how `cloudsentry scan --expect` knows what to look for.

resource "aws_network_acl" "wideopen" {
  count      = var.faults ? 1 : 0
  vpc_id     = aws_vpc.a.id
  subnet_ids = [for name, acl in local.subnet_acl : aws_subnet.a[name].id if acl == "wideopen"]

  ingress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "cloudsentry-a-wideopen", Fault = "CIS 5.2" }
}

# Denies 22 and 3389 before allowing everything else. CIS 5.2 passes because the first match wins.
resource "aws_network_acl" "denyssh" {
  count      = var.faults ? 1 : 0
  vpc_id     = aws_vpc.a.id
  subnet_ids = [aws_subnet.a["denyssh"].id]

  ingress {
    rule_no    = 90
    action     = "deny"
    protocol   = "tcp"
    cidr_block = "0.0.0.0/0"
    from_port  = 22
    to_port    = 22
  }

  ingress {
    rule_no    = 95
    action     = "deny"
    protocol   = "tcp"
    cidr_block = "0.0.0.0/0"
    from_port  = 3389
    to_port    = 3389
  }

  ingress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "cloudsentry-a-denyssh" }
}

# Lets everything in but only HTTPS out. Network ACLs are stateless, so the reply to an inbound
# SSH connection (from port 22 to the client's ephemeral port) is dropped on the way out.
resource "aws_network_acl" "noreturn" {
  count      = var.faults ? 1 : 0
  vpc_id     = aws_vpc.a.id
  subnet_ids = [aws_subnet.a["noreturn"].id]

  ingress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "tcp"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  tags = { Name = "cloudsentry-a-noreturn", Fault = "CIS 5.2" }
}

locals {
  world_groups = var.faults ? {
    ssh    = { protocol = "tcp", port = 22, cidr = "0.0.0.0/0", control = "CIS 5.3" }
    rdp    = { protocol = "tcp", port = 3389, cidr = "0.0.0.0/0", control = "CIS 5.3" }
    all    = { protocol = "-1", port = 0, cidr = "0.0.0.0/0", control = "CIS 5.3" }
    ssh-v6 = { protocol = "tcp", port = 22, cidr = "::/0", control = "CIS 5.4" }
  } : {}
}

resource "aws_security_group" "world" {
  for_each    = local.world_groups
  name        = "cloudsentry-${each.key}-world"
  description = "Seeded fault: ${each.key} open to the internet"
  vpc_id      = aws_vpc.a.id

  ingress {
    protocol         = each.value.protocol
    from_port        = each.value.port
    to_port          = each.value.port
    cidr_blocks      = strcontains(each.value.cidr, ":") ? [] : [each.value.cidr]
    ipv6_cidr_blocks = strcontains(each.value.cidr, ":") ? [each.value.cidr] : []
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "cloudsentry-${each.key}-world", Fault = each.value.control }
}
