"""Build the inventory from `terraform show -json`, so a problem shows up before anything exists.

In a plan, IDs don't exist yet, so resources are named by their Terraform address, and the links
between them (which VPC a group belongs to, which peering a route uses) come from the references
in the configuration section of the plan.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

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
    protocol_name,
)

ADDRESS = re.compile(r"^([a-z0-9_]+\.[A-Za-z0-9_-]+(?:\[[^\]]+\])?)")


def _walk(module: dict):
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from _walk(child)


def _tags(values: dict) -> dict[str, str]:
    tags = values.get("tags_all") or values.get("tags") or {}
    return {k: v for k, v in tags.items() if v is not None}


def _permissions(blocks: list[dict] | None) -> list[Permission]:
    out = []
    for block in blocks or []:
        proto = protocol_name(block.get("protocol"))
        ports = block.get("from_port"), block.get("to_port")
        cidrs = (block.get("cidr_blocks") or []) + (block.get("ipv6_cidr_blocks") or [])
        out += [Permission(proto, *ports, cidr=c) for c in cidrs]
        if block.get("self") or block.get("security_groups") or block.get("prefix_list_ids"):
            out.append(Permission(proto, *ports))
    return out


def _entries(values: dict) -> list[AclEntry]:
    out = []
    for direction, egress in (("ingress", False), ("egress", True)):
        for block in values.get(direction) or []:
            out.append(
                AclEntry(
                    number=block["rule_no"],
                    egress=egress,
                    allow=block["action"] == "allow",
                    protocol=protocol_name(block.get("protocol")),
                    cidr=block.get("cidr_block") or block.get("ipv6_cidr_block") or None,
                    from_port=block.get("from_port"),
                    to_port=block.get("to_port"),
                )
            )
    return out


class _Plan:
    def __init__(self, plan: dict):
        self.resources = [r for r in _walk(plan["planned_values"]["root_module"]) if r["mode"] == "managed"]
        self.addresses = {r["address"] for r in self.resources}
        config = plan.get("configuration", {}).get("root_module", {})
        self.expressions = {r["address"]: r.get("expressions", {}) for r in config.get("resources", [])}

    def of_type(self, *types: str):
        return [r for r in self.resources if r["type"] in types]

    def links(self, resource: dict, attribute: str) -> list[str]:
        """Addresses of the resources this attribute refers to, for example the VPC behind vpc_id."""
        config_address = resource["address"].split("[")[0]
        refs = self.expressions.get(config_address, {}).get(attribute, {}).get("references", [])
        found = []
        for ref in refs:
            match = ADDRESS.match(ref)
            if match and match.group(1) in self.addresses and match.group(1) not in found:
                found.append(match.group(1))
        return found

    def link(self, resource: dict, attribute: str) -> str | None:
        found = self.links(resource, attribute)
        return found[0] if len(found) == 1 else None


def load(path: str | Path) -> Inventory:
    plan = json.loads(Path(path).read_text())
    p = _Plan(plan)
    region = (plan.get("variables", {}).get("region") or {}).get("value", "plan")
    inv = Inventory(source=f"plan:{Path(path).name}", region=region)

    for r in p.of_type("aws_vpc"):
        inv.vpcs.append(Vpc(id=r["address"], cidr=r["values"].get("cidr_block"), tags=_tags(r["values"])))

    for r in p.of_type("aws_subnet"):
        inv.subnets[r["address"]] = p.link(r, "vpc_id")

    for r in p.of_type("aws_security_group", "aws_default_security_group"):
        v = r["values"]
        is_default = r["type"] == "aws_default_security_group"
        inv.groups.append(
            SecurityGroup(
                id=r["address"],
                name="default" if is_default else (v.get("name") or r["address"]),
                vpc_id=p.link(r, "vpc_id"),
                ingress=_permissions(v.get("ingress")),
                egress=_permissions(v.get("egress")),
                tags=_tags(v),
            )
        )

    for r in p.of_type("aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"):
        v = r["values"]
        group = inv.group(p.link(r, "security_group_id") or "")
        if group is None:
            group = SecurityGroup(id=r["address"], name=r["address"], vpc_id=None)
            inv.groups.append(group)
        rule = Permission(
            protocol_name(v.get("ip_protocol")),
            v.get("from_port"),
            v.get("to_port"),
            v.get("cidr_ipv4") or v.get("cidr_ipv6"),
        )
        (group.egress if r["type"].endswith("egress_rule") else group.ingress).append(rule)

    for r in p.of_type("aws_network_acl", "aws_default_network_acl"):
        is_default = r["type"] == "aws_default_network_acl"
        inv.acls.append(
            NetworkAcl(
                id=r["address"],
                vpc_id=p.link(r, "default_network_acl_id" if is_default else "vpc_id"),
                is_default=is_default,
                subnet_ids=p.links(r, "subnet_ids"),
                entries=_entries(r["values"]),
                tags=_tags(r["values"]),
            )
        )

    for r in p.of_type("aws_network_acl_rule"):
        v = r["values"]
        acl = next((a for a in inv.acls if a.id == p.link(r, "network_acl_id")), None)
        if acl:
            acl.entries.append(
                AclEntry(
                    number=v["rule_number"],
                    egress=bool(v.get("egress")),
                    allow=v["rule_action"] == "allow",
                    protocol=protocol_name(v.get("protocol")),
                    cidr=v.get("cidr_block") or v.get("ipv6_cidr_block") or None,
                    from_port=v.get("from_port"),
                    to_port=v.get("to_port"),
                )
            )

    for r in p.of_type("aws_route_table"):
        inv.route_tables.append(RouteTable(id=r["address"], vpc_id=p.link(r, "vpc_id"), tags=_tags(r["values"])))
    tables = {t.id: t for t in inv.route_tables}

    for r in p.of_type("aws_route"):
        table = tables.get(p.link(r, "route_table_id") or "")
        if table:
            v = r["values"]
            destination = v.get("destination_cidr_block") or v.get("destination_ipv6_cidr_block") or ""
            target = p.link(r, "vpc_peering_connection_id") or p.link(r, "gateway_id") or "unknown"
            table.routes.append(Route(destination, target))

    for r in p.of_type("aws_route_table_association"):
        table = tables.get(p.link(r, "route_table_id") or "")
        subnet = p.link(r, "subnet_id")
        if table and subnet:
            table.subnet_ids.append(subnet)

    for r in p.of_type("aws_vpc_peering_connection"):
        inv.peerings.append(Peering(r["address"], p.link(r, "vpc_id"), p.link(r, "peer_vpc_id")))

    for r in p.of_type("aws_flow_log"):
        vpc = inv.vpc(p.link(r, "vpc_id"))
        if vpc:
            vpc.flow_log_traffic.append(r["values"].get("traffic_type") or "")

    for r in p.of_type("aws_instance"):
        v = r["values"]
        options = (v.get("metadata_options") or [{}])[0] or {}
        inv.instances.append(
            Instance(
                id=r["address"],
                vpc_id=None,
                subnet_id=p.link(r, "subnet_id"),
                state="planned",
                public_ip=None,
                group_ids=p.links(r, "vpc_security_group_ids"),
                imds_tokens=options.get("http_tokens"),
                tags=_tags(v),
            )
        )

    _add_implicit_defaults(inv)
    return inv


def _add_implicit_defaults(inv: Inventory) -> None:
    """AWS gives every new VPC a default security group and network ACL that allow traffic.

    They never appear in a plan unless Terraform manages them, so without this a plan would look
    cleaner than the account it creates.
    """
    for vpc in inv.vpcs:
        if not any(g.is_default and g.vpc_id == vpc.id for g in inv.groups):
            inv.groups.append(
                SecurityGroup(
                    id=f"{vpc.id} (default security group)",
                    name="default",
                    vpc_id=vpc.id,
                    ingress=[Permission("all", None, None)],
                    egress=[Permission("all", None, None, cidr="0.0.0.0/0")],
                )
            )
        if not any(a.is_default and a.vpc_id == vpc.id for a in inv.acls):
            inv.acls.append(
                NetworkAcl(
                    id=f"{vpc.id} (default network ACL)",
                    vpc_id=vpc.id,
                    is_default=True,
                    entries=[
                        AclEntry(100, False, True, "all", "0.0.0.0/0"),
                        AclEntry(100, True, True, "all", "0.0.0.0/0"),
                    ],
                )
            )
