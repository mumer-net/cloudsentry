| Control | Severity | Resource | Detail |
| --- | --- | --- | --- |
| CIS 5.2 | high | `aws_network_acl.noreturn[0]` | inbound from 0.0.0.0/0 allowed on port 22, 3389 |
| CIS 5.2 | high | `aws_network_acl.wideopen[0]` | inbound from 0.0.0.0/0 allowed on port 22, 3389 |
| CIS 5.3 | high | `aws_security_group.world["all"]` | cloudsentry-all-world allows 0.0.0.0/0 on port 22, 3389 |
| CIS 5.3 | high | `aws_security_group.world["rdp"]` | cloudsentry-rdp-world allows 0.0.0.0/0 on port 3389 |
| CIS 5.3 | high | `aws_security_group.world["ssh"]` | cloudsentry-ssh-world allows 0.0.0.0/0 on port 22 |
| CIS 5.4 | high | `aws_security_group.world["ssh-v6"]` | cloudsentry-ssh-v6-world allows ::/0 on port 22 |
| CIS 3.7 | medium | `aws_vpc.b` | no flow log capturing rejected traffic |
| CIS 5.5 | medium | `aws_default_security_group.b` | default group in aws_vpc.b has 1 inbound, 1 outbound rules |
| CIS 5.7 | medium | `aws_instance.scenario["restricted"]` | cloudsentry-restricted still accepts IMDSv1 |
| CIS 5.6 | low | `aws_route_table.private` | routes 10.30.0.0/16 over aws_vpc_peering_connection.ab, all of aws_vpc.b |
10 findings (6 high, 3 medium, 1 low) in plan:plan-faults.json

Seeded faults detected: 10/10, missed 0, unexpected findings 0
