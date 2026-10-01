from cloudsentry import rules
from cloudsentry.model import (
    AclEntry,
    Instance,
    Inventory,
    NetworkAcl,
    Peering,
    Permission,
    Route,
    RouteTable,
    SecurityGroup,
    Vpc,
)


def inventory(**parts) -> Inventory:
    inv = Inventory(source="test", region="us-east-1")
    for name, items in parts.items():
        setattr(inv, name, items)
    return inv


def controls(inv: Inventory) -> list[tuple[str, str]]:
    return sorted((f.control, f.resource) for f in rules.run(inv))


def acl(*entries: AclEntry) -> Inventory:
    return inventory(acls=[NetworkAcl("acl-1", "vpc-1", False, entries=list(entries))])


def test_allow_all_acl_fails_5_2():
    findings = rules.run(acl(AclEntry(100, False, True, "all", "0.0.0.0/0")))
    assert [(f.control, f.detail) for f in findings] == [("CIS 5.2", "inbound from 0.0.0.0/0 allowed on port 22, 3389")]


def test_acl_deny_before_allow_passes():
    inv = acl(
        AclEntry(90, False, False, "tcp", "0.0.0.0/0", 22, 22),
        AclEntry(95, False, False, "tcp", "0.0.0.0/0", 3389, 3389),
        AclEntry(100, False, True, "all", "0.0.0.0/0"),
    )
    assert controls(inv) == []


def test_acl_order_is_by_rule_number_not_by_position():
    inv = acl(
        AclEntry(100, False, True, "all", "0.0.0.0/0"),
        AclEntry(90, False, False, "tcp", "0.0.0.0/0", 22, 22),
    )
    assert [f.detail for f in rules.run(inv)] == ["inbound from 0.0.0.0/0 allowed on port 3389"]


def test_ephemeral_range_that_includes_3389_fails():
    inv = acl(AclEntry(110, False, True, "tcp", "0.0.0.0/0", 1024, 65535))
    assert [f.detail for f in rules.run(inv)] == ["inbound from 0.0.0.0/0 allowed on port 3389"]


def test_ephemeral_range_split_around_3389_passes():
    inv = acl(
        AclEntry(110, False, True, "tcp", "0.0.0.0/0", 1024, 3388),
        AclEntry(120, False, True, "tcp", "0.0.0.0/0", 3390, 65535),
    )
    assert controls(inv) == []


def test_acl_rules_that_do_not_apply_to_the_whole_internet_are_ignored():
    inv = acl(
        AclEntry(100, False, True, "all", "10.0.0.0/8"),
        AclEntry(110, True, True, "all", "0.0.0.0/0"),
        AclEntry(120, False, True, "udp", "0.0.0.0/0", 0, 65535),
    )
    assert controls(inv) == []


def group(*ingress: Permission, name="web", group_id="sg-1") -> SecurityGroup:
    return SecurityGroup(group_id, name, "vpc-1", ingress=list(ingress))


def test_ssh_open_to_the_world_fails_5_3():
    inv = inventory(groups=[group(Permission("tcp", 22, 22, "0.0.0.0/0"))])
    assert controls(inv) == [("CIS 5.3", "sg-1")]


def test_all_traffic_rule_covers_both_admin_ports():
    inv = inventory(groups=[group(Permission("all", None, None, "0.0.0.0/0"))])
    assert [f.detail for f in rules.run(inv)] == ["web allows 0.0.0.0/0 on port 22, 3389"]


def test_port_range_covering_rdp_fails():
    inv = inventory(groups=[group(Permission("tcp", 3000, 4000, "0.0.0.0/0"))])
    assert [f.detail for f in rules.run(inv)] == ["web allows 0.0.0.0/0 on port 3389"]


def test_ipv6_world_fails_5_4_not_5_3():
    inv = inventory(groups=[group(Permission("tcp", 22, 22, "::/0"))])
    assert controls(inv) == [("CIS 5.4", "sg-1")]


def test_https_to_the_world_and_ssh_to_one_host_pass():
    inv = inventory(
        groups=[group(Permission("tcp", 443, 443, "0.0.0.0/0"), Permission("tcp", 22, 22, "198.51.100.7/32"))]
    )
    assert controls(inv) == []


def test_default_group_with_rules_fails_5_5():
    default = SecurityGroup("sg-d", "default", "vpc-1", egress=[Permission("all", None, None, "0.0.0.0/0")])
    empty = SecurityGroup("sg-e", "default", "vpc-2")
    assert controls(inventory(groups=[default, empty])) == [("CIS 5.5", "sg-d")]


def peering_inventory(destination: str) -> Inventory:
    return inventory(
        vpcs=[Vpc("vpc-a", "10.20.0.0/16", ["REJECT"]), Vpc("vpc-b", "10.30.0.0/16", ["REJECT"])],
        peerings=[Peering("pcx-1", "vpc-a", "vpc-b")],
        route_tables=[RouteTable("rtb-1", "vpc-a", routes=[Route(destination, "pcx-1")])],
    )


def test_route_to_the_whole_peer_vpc_fails_5_6():
    assert controls(peering_inventory("10.30.0.0/16")) == [("CIS 5.6", "rtb-1")]


def test_route_broader_than_the_peer_vpc_fails_5_6():
    assert controls(peering_inventory("10.0.0.0/8")) == [("CIS 5.6", "rtb-1")]


def test_route_to_one_peer_subnet_passes():
    assert controls(peering_inventory("10.30.1.0/28")) == []


def test_peering_seen_from_the_accepter_side():
    inv = peering_inventory("10.20.0.0/16")
    inv.route_tables[0].vpc_id = "vpc-b"
    assert controls(inv) == [("CIS 5.6", "rtb-1")]


def test_imdsv1_fails_5_7():
    inv = inventory(
        instances=[
            Instance("i-1", "vpc-1", "subnet-1", "running", None, imds_tokens="optional"),
            Instance("i-2", "vpc-1", "subnet-1", "running", None, imds_tokens="required"),
        ]
    )
    assert controls(inv) == [("CIS 5.7", "i-1")]


def test_flow_logs_must_capture_rejected_traffic():
    inv = inventory(
        vpcs=[
            Vpc("vpc-none", "10.1.0.0/16"),
            Vpc("vpc-accept", "10.2.0.0/16", ["ACCEPT"]),
            Vpc("vpc-reject", "10.3.0.0/16", ["REJECT"]),
            Vpc("vpc-all", "10.4.0.0/16", ["ALL"]),
        ]
    )
    assert controls(inv) == [("CIS 3.7", "vpc-accept"), ("CIS 3.7", "vpc-none")]


def test_seeded_faults_come_from_fault_tags():
    inv = inventory(
        vpcs=[Vpc("vpc-1", "10.0.0.0/16", tags={"Fault": "CIS 3.7"})],
        groups=[SecurityGroup("sg-1", "x", "vpc-1", tags={"Fault": "CIS 5.3, CIS 5.4"})],
    )
    assert rules.seeded_faults(inv) == {("CIS 3.7", "vpc-1"), ("CIS 5.3", "sg-1"), ("CIS 5.4", "sg-1")}
