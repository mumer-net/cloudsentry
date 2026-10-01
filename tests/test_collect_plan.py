"""Plan-time checks against `terraform show -json` output of the lab, in both modes."""

import json
from collections import Counter
from pathlib import Path

from cloudsentry import collect_plan, rules

FIXTURES = Path(__file__).parent / "fixtures"


def test_faulty_plan_finds_exactly_the_seeded_faults():
    inv = collect_plan.load(FIXTURES / "plan-faults.json")
    findings = {(f.control, f.resource) for f in rules.run(inv)}
    assert findings == rules.seeded_faults(inv)
    assert Counter(control for control, _ in findings) == {
        "CIS 5.2": 2,
        "CIS 5.3": 3,
        "CIS 5.4": 1,
        "CIS 5.5": 1,
        "CIS 5.6": 1,
        "CIS 5.7": 1,
        "CIS 3.7": 1,
    }


def test_clean_plan_has_no_findings():
    inv = collect_plan.load(FIXTURES / "plan-clean.json")
    assert rules.run(inv) == []
    assert rules.seeded_faults(inv) == set()


def test_references_link_resources_together():
    inv = collect_plan.load(FIXTURES / "plan-faults.json")
    default_b = next(g for g in inv.groups if g.id == "aws_default_security_group.b")
    assert default_b.vpc_id == "aws_vpc.b"
    assert [(p.requester_vpc_id, p.accepter_vpc_id) for p in inv.peerings] == [("aws_vpc.a", "aws_vpc.b")]
    assert inv.vpc("aws_vpc.a").flow_log_traffic == ["REJECT"]
    private = next(t for t in inv.route_tables if t.id == "aws_route_table.private")
    assert [(r.destination, r.target) for r in private.routes] == [("10.30.0.0/16", "aws_vpc_peering_connection.ab")]


def test_unmanaged_defaults_are_treated_as_aws_creates_them(tmp_path):
    # A VPC with nothing else: AWS will give it an allow-all default network ACL and a default
    # security group with rules, and no flow log.
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_vpc.only",
                        "mode": "managed",
                        "type": "aws_vpc",
                        "name": "only",
                        "values": {"cidr_block": "10.9.0.0/16"},
                    }
                ]
            }
        },
        "configuration": {"root_module": {"resources": []}},
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    found = sorted((f.control, f.resource) for f in rules.run(collect_plan.load(path)))
    assert found == [
        ("CIS 3.7", "aws_vpc.only"),
        ("CIS 5.2", "aws_vpc.only (default network ACL)"),
        ("CIS 5.5", "aws_vpc.only (default security group)"),
    ]
