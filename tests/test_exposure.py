from cloudsentry import exposure
from cloudsentry.model import AclEntry, Route, RouteTable

SOURCE = "192.0.2.10"


def results(lab):
    return {(r.name.removeprefix("cloudsentry-"), r.port): r for r in exposure.analyze(lab, SOURCE)}


def test_each_case_is_blocked_where_expected(lab):
    blocked = {key: r.blocked_by for key, r in results(lab).items()}
    assert blocked == {
        ("all-open", 22): None,
        ("all-open", 3389): None,
        ("nacl-deny", 22): "network ACL inbound rule 90",
        ("nacl-deny", 3389): "network ACL inbound rule 95",
        ("nacl-noreturn", 22): "network ACL outbound (no return path)",
        ("nacl-noreturn", 3389): "security group",
        ("no-route", 22): "no route to an internet gateway",
        ("no-route", 3389): "security group",
        ("open-rdp", 22): "security group",
        ("open-rdp", 3389): None,
        ("open-ssh", 22): None,
        ("open-ssh", 3389): "security group",
        ("private", 22): "no public IP",
        ("private", 3389): "no public IP",
        ("restricted", 22): "security group",
        ("restricted", 3389): "security group",
    }


def test_security_group_view_flags_more_than_is_reachable(lab):
    found = results(lab).values()
    naive = {(r.name, r.port) for r in found if r.naive}
    reachable = {(r.name, r.port) for r in found if r.reachable}
    assert reachable < naive
    assert len(naive) == 8
    assert len(reachable) == 4


def test_the_allowed_source_itself_can_reach_the_restricted_instance(lab):
    [ssh] = [r for r in exposure.analyze(lab, "198.51.100.7") if r.name == "cloudsentry-restricted" and r.port == 22]
    assert ssh.reachable


def test_stopped_instances_are_skipped(lab):
    lab.instances[0].state = "stopped"
    assert all(r.instance != lab.instances[0].id for r in exposure.analyze(lab, SOURCE))


def test_allowed_ports_first_match_wins():
    rules = [
        AclEntry(90, True, False, "tcp", "0.0.0.0/0", 50000, 50010),
        AclEntry(100, True, True, "tcp", "0.0.0.0/0", 1024, 65535),
    ]
    assert exposure.allowed_ports(rules, SOURCE, 1024, 65535) == [(1024, 49999), (50011, 65535)]


def test_allowed_ports_ignores_rules_for_other_sources_and_protocols():
    rules = [
        AclEntry(90, True, True, "tcp", "10.0.0.0/8", 0, 65535),
        AclEntry(95, True, True, "udp", "0.0.0.0/0", 0, 65535),
    ]
    assert exposure.allowed_ports(rules, SOURCE, 1024, 65535) == []


def test_route_lookup_uses_the_longest_prefix():
    table = RouteTable(
        "rtb-1",
        "vpc-a",
        routes=[Route("0.0.0.0/0", "igw-1"), Route("192.0.2.0/24", "pcx-1"), Route("pl-123", "vpce-1")],
    )
    assert exposure.route_target(table, SOURCE) == "pcx-1"
    assert exposure.route_target(table, "8.8.8.8") == "igw-1"
    assert exposure.route_target(None, SOURCE) is None
