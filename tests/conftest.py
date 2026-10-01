import pytest

from cloudsentry.model import AclEntry, Instance, Inventory, NetworkAcl, Permission, Route, RouteTable, SecurityGroup

EVERYTHING = AclEntry(100, False, True, "all", "0.0.0.0/0")
EVERYTHING_OUT = AclEntry(100, True, True, "all", "0.0.0.0/0")


def world(port: int | None) -> Permission:
    if port is None:
        return Permission("all", None, None, "0.0.0.0/0")
    return Permission("tcp", port, port, "0.0.0.0/0")


@pytest.fixture
def lab() -> Inventory:
    """The faulty lab as the live collector would see it, one instance per exposure case."""
    inv = Inventory(source="test", region="us-east-1")
    subnets = ["open", "denyssh", "noreturn", "noroute", "private"]
    inv.subnets = {f"subnet-{s}": "vpc-a" for s in subnets}
    inv.route_tables = [
        RouteTable(
            "rtb-public",
            "vpc-a",
            subnet_ids=["subnet-open", "subnet-denyssh", "subnet-noreturn"],
            routes=[Route("10.20.0.0/16", "local"), Route("0.0.0.0/0", "igw-1")],
        ),
        RouteTable(
            "rtb-private",
            "vpc-a",
            subnet_ids=["subnet-noroute", "subnet-private"],
            routes=[Route("10.20.0.0/16", "local"), Route("10.30.0.0/16", "pcx-1")],
        ),
        RouteTable("rtb-main", "vpc-a", main=True, routes=[Route("10.20.0.0/16", "local")]),
    ]
    inv.acls = [
        NetworkAcl(
            "acl-wide",
            "vpc-a",
            False,
            ["subnet-open", "subnet-noroute", "subnet-private"],
            [EVERYTHING, EVERYTHING_OUT],
        ),
        NetworkAcl(
            "acl-denyssh",
            "vpc-a",
            False,
            ["subnet-denyssh"],
            [
                AclEntry(90, False, False, "tcp", "0.0.0.0/0", 22, 22),
                AclEntry(95, False, False, "tcp", "0.0.0.0/0", 3389, 3389),
                EVERYTHING,
                EVERYTHING_OUT,
            ],
        ),
        NetworkAcl(
            "acl-noreturn",
            "vpc-a",
            False,
            ["subnet-noreturn"],
            [EVERYTHING, AclEntry(100, True, True, "tcp", "0.0.0.0/0", 443, 443)],
        ),
        NetworkAcl("acl-default", "vpc-a", True, [], []),
    ]
    inv.groups = [
        SecurityGroup("sg-ssh", "ssh-world", "vpc-a", ingress=[world(22)]),
        SecurityGroup("sg-rdp", "rdp-world", "vpc-a", ingress=[world(3389)]),
        SecurityGroup("sg-all", "all-world", "vpc-a", ingress=[world(None)]),
        SecurityGroup("sg-restricted", "restricted", "vpc-a", ingress=[Permission("tcp", 22, 22, "198.51.100.7/32")]),
    ]
    cases = {
        "open-ssh": ("open", True, "sg-ssh"),
        "nacl-deny": ("denyssh", True, "sg-ssh"),
        "nacl-noreturn": ("noreturn", True, "sg-ssh"),
        "no-route": ("noroute", True, "sg-ssh"),
        "private": ("private", False, "sg-ssh"),
        "open-rdp": ("open", True, "sg-rdp"),
        "restricted": ("open", True, "sg-restricted"),
        "all-open": ("open", True, "sg-all"),
    }
    for number, (name, (subnet, public, group)) in enumerate(cases.items(), start=1):
        inv.instances.append(
            Instance(
                id=f"i-{name}",
                vpc_id="vpc-a",
                subnet_id=f"subnet-{subnet}",
                state="running",
                public_ip=f"203.0.113.{number}" if public else None,
                group_ids=[group],
                imds_tokens="required",
                tags={"Name": f"cloudsentry-{name}"},
            )
        )
    return inv
