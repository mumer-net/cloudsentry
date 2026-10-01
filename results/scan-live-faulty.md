| Control | Severity | Resource | Detail |
| --- | --- | --- | --- |
| CIS 5.2 | high | `acl-0af46e1d72222d852` | inbound from 0.0.0.0/0 allowed on port 22, 3389 |
| CIS 5.2 | high | `acl-0d770d9af825e702d` | inbound from 0.0.0.0/0 allowed on port 22, 3389 |
| CIS 5.3 | high | `sg-032c407c8cd9d4145` | cloudsentry-ssh-world allows 0.0.0.0/0 on port 22 |
| CIS 5.3 | high | `sg-09be4969aaa0583b8` | cloudsentry-all-world allows 0.0.0.0/0 on port 22, 3389 |
| CIS 5.3 | high | `sg-0bf892ef5b8fb73ed` | cloudsentry-rdp-world allows 0.0.0.0/0 on port 3389 |
| CIS 5.4 | high | `sg-072d9a294a62a8285` | cloudsentry-ssh-v6-world allows ::/0 on port 22 |
| CIS 3.7 | medium | `vpc-0eab9928ee5baa23f` | no flow log capturing rejected traffic |
| CIS 5.5 | medium | `sg-0425bfa0be911f518` | default group in vpc-0eab9928ee5baa23f has 1 inbound, 1 outbound rules |
| CIS 5.7 | medium | `i-0710f14fb4a52ccb1` | cloudsentry-restricted still accepts IMDSv1 |
| CIS 5.6 | low | `rtb-05da573e0c026ce9b` | routes 10.30.0.0/16 over pcx-04f127d70bde6e6ad, all of vpc-0eab9928ee5baa23f |
10 findings (6 high, 3 medium, 1 low) in aws:us-east-1

Seeded faults detected: 10/10, missed 0, unexpected findings 0
