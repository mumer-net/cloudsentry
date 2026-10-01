"""Which instance ports can a given internet address actually reach?

A security group rule open to 0.0.0.0/0 is what most tools alert on, but the packet also has to
get past a public IP, the subnet's network ACL (both ways, because ACLs are stateless) and a
route back to an internet gateway. This follows the packet in that order and names the first
thing that stops it.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from cloudsentry.model import AclEntry, Instance, Inventory, RouteTable, cidr_contains

# Clients pick their source port from this range (macOS uses 49152-65535, Linux 32768-60999).
CLIENT_PORTS = (1024, 65535)


@dataclass
class Exposure:
    instance: str
    name: str
    port: int
    naive: bool
    reachable: bool
    blocked_by: str | None


def naive_open(inv: Inventory, instance: Instance, port: int) -> bool:
    """The usual alert: any attached group allows 0.0.0.0/0 on the port."""
    groups = filter(None, (inv.group(g) for g in instance.group_ids))
    return any(r.cidr == "0.0.0.0/0" and r.covers(port) for g in groups for r in g.ingress)


def allowed_ports(entries: list[AclEntry], ip: str, low: int, high: int) -> list[tuple[int, int]]:
    """Port ranges within low..high that a network ACL allows for TCP traffic to or from ip.

    Rules are checked in number order and the first match decides each port, so the ranges are
    carved up rule by rule. Whatever no rule matched falls through to the implicit deny.
    """
    undecided = [(low, high)]
    allowed = []
    for rule in entries:
        if rule.protocol not in ("tcp", "all") or not cidr_contains(rule.cidr, ip):
            continue
        rule_low, rule_high = rule.port_range()
        remaining = []
        for start, end in undecided:
            lo, hi = max(start, rule_low), min(end, rule_high)
            if lo > hi:
                remaining.append((start, end))
                continue
            if rule.allow:
                allowed.append((lo, hi))
            if start < lo:
                remaining.append((start, lo - 1))
            if hi < end:
                remaining.append((hi + 1, end))
        undecided = remaining
        if not undecided:
            break
    return allowed


def _matches(rule: AclEntry, ip: str, port: int) -> bool:
    low, high = rule.port_range()
    return rule.protocol in ("tcp", "all") and cidr_contains(rule.cidr, ip) and low <= port <= high


def route_target(table: RouteTable | None, ip: str) -> str | None:
    """Longest-prefix match, the way the VPC router picks a route."""
    best, best_len = None, -1
    address = ipaddress.ip_address(ip)
    for route in table.routes if table else []:
        try:
            network = ipaddress.ip_network(route.destination, strict=False)
        except ValueError:
            continue
        if network.version == address.version and address in network and network.prefixlen > best_len:
            best, best_len = route.target, network.prefixlen
    return best


def check(inv: Inventory, instance: Instance, port: int, source: str) -> str | None:
    """None if source can open a TCP connection to the port, otherwise what blocks it."""
    if not instance.public_ip:
        return "no public IP"
    acl = inv.acl_for(instance.subnet_id or "")
    inbound = acl.rules(egress=False) if acl else []
    if not allowed_ports(inbound, source, port, port):
        rule = next((r for r in inbound if _matches(r, source, port)), None)
        return f"network ACL inbound rule {rule.number}" if rule else "network ACL inbound (no rule allows it)"
    groups = filter(None, (inv.group(g) for g in instance.group_ids))
    if not any(cidr_contains(r.cidr, source) and r.covers(port) for g in groups for r in g.ingress):
        return "security group"
    outbound = acl.rules(egress=True) if acl else []
    if not allowed_ports(outbound, source, *CLIENT_PORTS):
        return "network ACL outbound (no return path)"
    target = route_target(inv.route_table_for(instance.subnet_id or ""), source)
    if not (target or "").startswith("igw-"):
        return "no route to an internet gateway"
    return None


def analyze(inv: Inventory, source: str, ports: tuple[int, ...] = (22, 3389)) -> list[Exposure]:
    results = []
    for instance in sorted(inv.instances, key=lambda i: i.name):
        if instance.state != "running":
            continue
        for port in ports:
            blocked = check(inv, instance, port, source)
            naive = naive_open(inv, instance, port)
            results.append(Exposure(instance.id, instance.name, port, naive, blocked is None, blocked))
    return results
