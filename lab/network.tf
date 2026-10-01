locals {
  # "public" subnets use the route table with the internet gateway route.
  subnets = {
    open     = { cidr = "10.20.1.0/24", public = true }
    denyssh  = { cidr = "10.20.2.0/24", public = true }
    noreturn = { cidr = "10.20.3.0/24", public = true }
    noroute  = { cidr = "10.20.4.0/24", public = false }
    private  = { cidr = "10.20.5.0/24", public = false }
  }

  # The clean lab gives every subnet the same network ACL.
  subnet_acl = var.faults ? {
    open     = "wideopen"
    denyssh  = "denyssh"
    noreturn = "noreturn"
    noroute  = "wideopen"
    private  = "wideopen"
  } : { for name in keys(local.subnets) : name => "standard" }
}

resource "aws_vpc" "a" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "cloudsentry-a" }
}

resource "aws_internet_gateway" "a" {
  vpc_id = aws_vpc.a.id
  tags   = { Name = "cloudsentry-a" }
}

resource "aws_subnet" "a" {
  for_each          = local.subnets
  vpc_id            = aws_vpc.a.id
  cidr_block        = each.value.cidr
  availability_zone = var.az
  tags              = { Name = "cloudsentry-a-${each.key}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.a.id
  tags   = { Name = "cloudsentry-a-public" }
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.a.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.a.id
  tags   = merge({ Name = "cloudsentry-a-private" }, var.faults ? { Fault = "CIS 5.6" } : {})
}

resource "aws_route_table_association" "a" {
  for_each       = local.subnets
  subnet_id      = aws_subnet.a[each.key].id
  route_table_id = each.value.public ? aws_route_table.public.id : aws_route_table.private.id
}

# Nothing uses the default ACLs, and an ACL with no rules denies everything.
resource "aws_default_network_acl" "a" {
  default_network_acl_id = aws_vpc.a.default_network_acl_id
  tags                   = { Name = "cloudsentry-a-default" }

  lifecycle {
    ignore_changes = [subnet_ids]
  }
}

resource "aws_default_security_group" "a" {
  vpc_id = aws_vpc.a.id
  tags   = { Name = "cloudsentry-a-default" }
}

resource "aws_network_acl" "standard" {
  count      = var.faults ? 0 : 1
  vpc_id     = aws_vpc.a.id
  subnet_ids = [for name, acl in local.subnet_acl : aws_subnet.a[name].id if acl == "standard"]

  ingress {
    rule_no    = 100
    action     = "allow"
    protocol   = "tcp"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Return traffic for connections the instances open. One 1024-65535 rule would include 3389
  # and fail CIS 5.2, so the range skips that port.
  ingress {
    rule_no    = 110
    action     = "allow"
    protocol   = "tcp"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 3388
  }

  ingress {
    rule_no    = 120
    action     = "allow"
    protocol   = "tcp"
    cidr_block = "0.0.0.0/0"
    from_port  = 3390
    to_port    = 65535
  }

  ingress {
    rule_no    = 130
    action     = "allow"
    protocol   = "-1"
    cidr_block = "10.0.0.0/8"
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

  tags = { Name = "cloudsentry-a-standard" }
}
