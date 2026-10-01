"""The parts of a VPC that the checks look at.

Both collectors fill the same model: collect_aws from the live EC2 API, collect_plan from a
Terraform plan. The rules never know which one they are reading.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

PROTOCOLS = {"-1": "all", "6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}


def protocol_name(value: str | int | None) -> str:
    text = str(value).lower() if value is not None else "-1"
    return PROTOCOLS.get(text, text)


def cidr_contains(cidr: str | None, ip: str) -> bool:
    if not cidr:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


@dataclass
class Permission:
    """One security group rule for one source. cidr is None when the source is a group or prefix list."""

    protocol: str
    from_port: int | None
    to_port: int | None
    cidr: str | None = None

    def covers(self, port: int) -> bool:
        if self.protocol == "all":
            return True
        if self.protocol != "tcp":
            return False
        if self.from_port is None or self.to_port is None or self.from_port < 0:
            return True
        return self.from_port <= port <= self.to_port


@dataclass
class SecurityGroup:
    id: str
    name: str
    vpc_id: str | None
    ingress: list[Permission] = field(default_factory=list)
    egress: list[Permission] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def is_default(self) -> bool:
        return self.name == "default"


@dataclass
class AclEntry:
    number: int
    egress: bool
    allow: bool
    protocol: str
    cidr: str | None
    from_port: int | None = None
    to_port: int | None = None

    def port_range(self) -> tuple[int, int]:
        if self.protocol == "all" or self.from_port is None or self.to_port is None:
            return 0, 65535
        return self.from_port, self.to_port


@dataclass
class NetworkAcl:
    id: str
    vpc_id: str | None
    is_default: bool
    subnet_ids: list[str] = field(default_factory=list)
    entries: list[AclEntry] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    def rules(self, egress: bool) -> list[AclEntry]:
        return sorted((e for e in self.entries if e.egress == egress), key=lambda e: e.number)


@dataclass
class Route:
    destination: str
    target: str


@dataclass
class RouteTable:
    id: str
    vpc_id: str | None
    main: bool = False
    subnet_ids: list[str] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class Vpc:
    id: str
    cidr: str | None
    flow_log_traffic: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class Peering:
    id: str
    requester_vpc_id: str | None
    accepter_vpc_id: str | None


@dataclass
class Instance:
    id: str
    vpc_id: str | None
    subnet_id: str | None
    state: str
    public_ip: str | None
    group_ids: list[str] = field(default_factory=list)
    imds_tokens: str | None = None
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.tags.get("Name", self.id)


@dataclass
class Inventory:
    source: str
    region: str
    vpcs: list[Vpc] = field(default_factory=list)
    subnets: dict[str, str | None] = field(default_factory=dict)
    groups: list[SecurityGroup] = field(default_factory=list)
    acls: list[NetworkAcl] = field(default_factory=list)
    route_tables: list[RouteTable] = field(default_factory=list)
    peerings: list[Peering] = field(default_factory=list)
    instances: list[Instance] = field(default_factory=list)

    def vpc(self, vpc_id: str | None) -> Vpc | None:
        return next((v for v in self.vpcs if v.id == vpc_id), None)

    def group(self, group_id: str) -> SecurityGroup | None:
        return next((g for g in self.groups if g.id == group_id), None)

    def acl_for(self, subnet_id: str) -> NetworkAcl | None:
        explicit = next((a for a in self.acls if subnet_id in a.subnet_ids), None)
        if explicit:
            return explicit
        vpc_id = self.subnets.get(subnet_id)
        return next((a for a in self.acls if a.is_default and a.vpc_id == vpc_id), None)

    def route_table_for(self, subnet_id: str) -> RouteTable | None:
        explicit = next((t for t in self.route_tables if subnet_id in t.subnet_ids), None)
        if explicit:
            return explicit
        vpc_id = self.subnets.get(subnet_id)
        return next((t for t in self.route_tables if t.main and t.vpc_id == vpc_id), None)

    def tagged(self):
        """Every resource that can carry the lab's Fault tag."""
        yield from self.vpcs
        yield from self.groups
        yield from self.acls
        yield from self.route_tables
        yield from self.instances
