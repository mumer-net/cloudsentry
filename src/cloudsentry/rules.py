"""Seven networking checks from the CIS AWS Foundations Benchmark v5.0.0."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from cloudsentry.model import Inventory

ADMIN_PORTS = (22, 3389)

CONTROLS = {
    "CIS 5.2": ("high", "No network ACL allows ingress from 0.0.0.0/0 to remote administration ports"),
    "CIS 5.3": ("high", "No security group allows ingress from 0.0.0.0/0 to remote administration ports"),
    "CIS 5.4": ("high", "No security group allows ingress from ::/0 to remote administration ports"),
    "CIS 5.5": ("medium", "The default security group of every VPC restricts all traffic"),
    "CIS 5.6": ("low", "Routing tables for VPC peering are least access"),
    "CIS 5.7": ("medium", "EC2 instances only allow IMDSv2"),
    "CIS 3.7": ("medium", "VPC flow logging is enabled in all VPCs"),
}


@dataclass(frozen=True)
class Finding:
    control: str
    resource: str
    region: str
    detail: str

    @property
    def severity(self) -> str:
        return CONTROLS[self.control][0]


def _ports(ports: list[int]) -> str:
    return ", ".join(str(p) for p in ports)


def nacl_admin_ports(inv: Inventory):
    for acl in inv.acls:
        # Rules are evaluated in order and the first match wins, so a deny for 22 at rule 90
        # makes a later allow-all at rule 100 harmless for that port.
        open_ports = []
        for port in ADMIN_PORTS:
            for rule in acl.rules(egress=False):
                low, high = rule.port_range()
                if rule.cidr == "0.0.0.0/0" and rule.protocol in ("tcp", "all") and low <= port <= high:
                    if rule.allow:
                        open_ports.append(port)
                    break
        if open_ports:
            yield Finding("CIS 5.2", acl.id, inv.region, f"inbound from 0.0.0.0/0 allowed on port {_ports(open_ports)}")


def _world_open(inv: Inventory, control: str, world: str):
    for group in inv.groups:
        ports = [p for p in ADMIN_PORTS if any(r.cidr == world and r.covers(p) for r in group.ingress)]
        if ports:
            yield Finding(control, group.id, inv.region, f"{group.name} allows {world} on port {_ports(ports)}")


def sg_admin_ports_ipv4(inv: Inventory):
    yield from _world_open(inv, "CIS 5.3", "0.0.0.0/0")


def sg_admin_ports_ipv6(inv: Inventory):
    yield from _world_open(inv, "CIS 5.4", "::/0")


def default_group_closed(inv: Inventory):
    for group in inv.groups:
        if group.is_default and (group.ingress or group.egress):
            rules = f"{len(group.ingress)} inbound, {len(group.egress)} outbound"
            yield Finding("CIS 5.5", group.id, inv.region, f"default group in {group.vpc_id} has {rules} rules")


def peering_least_access(inv: Inventory):
    # CIS lists 5.6 as a manual check. My automated version flags a peering route that sends the
    # peer's entire VPC range, when least access would route only the subnets that need to talk.
    for table in inv.route_tables:
        for route in table.routes:
            peering = next((p for p in inv.peerings if p.id == route.target), None)
            if not peering:
                continue
            ends = (peering.requester_vpc_id, peering.accepter_vpc_id)
            peer = inv.vpc(ends[1] if ends[0] == table.vpc_id else ends[0])
            if not peer or not peer.cidr:
                continue
            try:
                routed = ipaddress.ip_network(route.destination, strict=False)
                whole = ipaddress.ip_network(peer.cidr)
            except ValueError:
                continue
            if routed.version == whole.version and whole.subnet_of(routed):
                yield Finding(
                    "CIS 5.6", table.id, inv.region, f"routes {route.destination} over {peering.id}, all of {peer.id}"
                )


def imds_v2_only(inv: Inventory):
    for instance in inv.instances:
        if instance.imds_tokens == "optional":
            yield Finding("CIS 5.7", instance.id, inv.region, f"{instance.name} still accepts IMDSv1")


def flow_logs_enabled(inv: Inventory):
    for vpc in inv.vpcs:
        if not {"ALL", "REJECT"} & set(vpc.flow_log_traffic):
            yield Finding("CIS 3.7", vpc.id, inv.region, "no flow log capturing rejected traffic")


CHECKS = [
    nacl_admin_ports,
    sg_admin_ports_ipv4,
    sg_admin_ports_ipv6,
    default_group_closed,
    peering_least_access,
    imds_v2_only,
    flow_logs_enabled,
]


def run(inv: Inventory) -> list[Finding]:
    return [finding for check in CHECKS for finding in check(inv)]


def seeded_faults(inv: Inventory) -> set[tuple[str, str]]:
    """The (control, resource) pairs the lab says it broke, read from each resource's Fault tag."""
    expected = set()
    for resource in inv.tagged():
        for control in filter(None, (c.strip() for c in resource.tags.get("Fault", "").split(","))):
            expected.add((control, resource.id))
    return expected
