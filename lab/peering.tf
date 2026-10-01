resource "aws_vpc" "b" {
  cidr_block = "10.30.0.0/16"
  tags       = merge({ Name = "cloudsentry-b" }, var.faults ? { Fault = "CIS 3.7" } : {})
}

resource "aws_default_network_acl" "b" {
  default_network_acl_id = aws_vpc.b.default_network_acl_id
  tags                   = { Name = "cloudsentry-b-default" }

  lifecycle {
    ignore_changes = [subnet_ids]
  }
}

# The seeded fault puts back the two rules AWS gives every new VPC's default group.
resource "aws_default_security_group" "b" {
  vpc_id = aws_vpc.b.id

  dynamic "ingress" {
    for_each = var.faults ? [1] : []
    content {
      protocol  = "-1"
      from_port = 0
      to_port   = 0
      self      = true
    }
  }

  dynamic "egress" {
    for_each = var.faults ? [1] : []
    content {
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = merge({ Name = "cloudsentry-b-default" }, var.faults ? { Fault = "CIS 5.5" } : {})
}

resource "aws_vpc_peering_connection" "ab" {
  vpc_id      = aws_vpc.a.id
  peer_vpc_id = aws_vpc.b.id
  auto_accept = true
  tags        = { Name = "cloudsentry-a-to-b" }
}

# Least access routes only the subnet that needs to talk. The seeded fault routes all of VPC B.
resource "aws_route" "a_to_b" {
  route_table_id            = aws_route_table.private.id
  destination_cidr_block    = var.faults ? "10.30.0.0/16" : "10.30.1.0/28"
  vpc_peering_connection_id = aws_vpc_peering_connection.ab.id
}

resource "aws_route_table" "b" {
  vpc_id = aws_vpc.b.id
  tags   = { Name = "cloudsentry-b" }
}

resource "aws_route" "b_to_a" {
  route_table_id            = aws_route_table.b.id
  destination_cidr_block    = "10.20.5.0/28"
  vpc_peering_connection_id = aws_vpc_peering_connection.ab.id
}
