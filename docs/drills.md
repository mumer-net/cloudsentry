# Drills

Things I ran by hand while building CloudSentry, and what I saw.

## First scan of a new AWS account

Before the lab existed, I scanned every region of my new account with the read-only profile:

```bash
uv run cloudsentry scan --all-regions --profile cloudsentry-ro
```

Result: 51 findings (17 high, 34 medium, 0 low) in 17 regions.

That is exactly three per region, and it matches the default VPC that AWS creates in every region:

- one high: the default network ACL allows all inbound traffic from 0.0.0.0/0 (CIS 5.2)
- two medium: the default security group has rules (CIS 5.5), and the VPC has no flow log (CIS 3.7)

So a brand new account fails three CIS networking controls in every region before you deploy
anything.

## Probing the exposure lab by hand

With the faulty lab applied, I tried five TCP connections from my laptop with bash's `/dev/tcp`
before running the exposure check:

| Instance and port | Result |
| --- | --- |
| open-ssh:22 | open |
| open-rdp:3389 | open |
| nacl-deny:22 | blocked |
| nacl-noreturn:22 | blocked |
| no-route:22 | blocked |

All three blocked instances have a security group that allows port 22 from 0.0.0.0/0, so a
security-group-only check flags them. The dry run of `cloudsentry exposure` named a different
cause for each one: `network ACL inbound rule 90`, `network ACL outbound (no return path)`, and
`no route to an internet gateway`. The three full runs with probes agreed with every row.

## Fixing a fault in the console

I started the history database, applied the faulty lab, and scanned it:

```text
10 findings (6 high, 3 medium, 1 low) in aws:us-east-1
Saved scan 1 of aws:us-east-1: 10 new, 0 fixed
```

Then I fixed one fault by hand the way someone on call would. In the EC2 console I opened
`cloudsentry-restricted`, went to Actions, Instance settings, Modify instance metadata options,
and set IMDSv2 to Required. I scanned again:

```text
9 findings (6 high, 2 medium, 1 low) in aws:us-east-1
Saved scan 2 of aws:us-east-1: 0 new, 1 fixed
```

`cloudsentry history` showed both scans, the severity counts going from 6/3/1 to 6/2/1, and
`fixed: CIS 5.7` on that instance. The nine findings still open kept the time they were first
seen in scan 1.
