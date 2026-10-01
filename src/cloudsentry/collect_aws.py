"""Read VPC network settings from the EC2 API. Every call is a read-only Describe."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import boto3

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

LIVE_STATES = ["pending", "running", "stopping", "stopped"]


def _tags(item: dict) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in item.get("Tags", [])}


def _pages(client, operation: str, key: str, **kwargs):
    for page in client.get_paginator(operation).paginate(**kwargs):
        yield from page[key]


def _permissions(rules: list[dict]) -> list[Permission]:
    out = []
    for rule in rules:
        proto = protocol_name(rule.get("IpProtocol"))
        ports = rule.get("FromPort"), rule.get("ToPort")
        sources = [r["CidrIp"] for r in rule.get("IpRanges", [])]
        sources += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
        out += [Permission(proto, *ports, cidr=c) for c in sources]
        if rule.get("UserIdGroupPairs") or rule.get("PrefixListIds"):
            out.append(Permission(proto, *ports, cidr=None))
    return out


def _acl_entry(entry: dict) -> AclEntry:
    ports = entry.get("PortRange") or {}
    return AclEntry(
        number=entry["RuleNumber"],
        egress=entry["Egress"],
        allow=entry["RuleAction"] == "allow",
        protocol=protocol_name(entry.get("Protocol")),
        cidr=entry.get("CidrBlock") or entry.get("Ipv6CidrBlock"),
        from_port=ports.get("From"),
        to_port=ports.get("To"),
    )


def _route_target(route: dict) -> str:
    for key in ("GatewayId", "VpcPeeringConnectionId", "NatGatewayId", "TransitGatewayId", "NetworkInterfaceId"):
        if route.get(key):
            return route[key]
    return "unknown"


def _primary_groups(instance: dict) -> list[str]:
    # The public IP belongs to the primary network interface, so its groups are the ones that matter.
    for eni in instance.get("NetworkInterfaces", []):
        if eni.get("Attachment", {}).get("DeviceIndex") == 0:
            return [g["GroupId"] for g in eni.get("Groups", [])]
    return [g["GroupId"] for g in instance.get("SecurityGroups", [])]


def collect(session: boto3.Session, region: str, tag: tuple[str, str] | None = None) -> Inventory:
    ec2 = session.client("ec2", region_name=region)
    inv = Inventory(source=f"aws:{region}", region=region)

    vpc_filter = [{"Name": f"tag:{tag[0]}", "Values": [tag[1]]}] if tag else []
    for v in _pages(ec2, "describe_vpcs", "Vpcs", Filters=vpc_filter):
        inv.vpcs.append(Vpc(id=v["VpcId"], cidr=v.get("CidrBlock"), tags=_tags(v)))
    vpc_ids = [v.id for v in inv.vpcs]
    if not vpc_ids:
        return inv
    in_vpcs = [{"Name": "vpc-id", "Values": vpc_ids}]

    for s in _pages(ec2, "describe_subnets", "Subnets", Filters=in_vpcs):
        inv.subnets[s["SubnetId"]] = s["VpcId"]

    for g in _pages(ec2, "describe_security_groups", "SecurityGroups", Filters=in_vpcs):
        inv.groups.append(
            SecurityGroup(
                id=g["GroupId"],
                name=g["GroupName"],
                vpc_id=g.get("VpcId"),
                ingress=_permissions(g.get("IpPermissions", [])),
                egress=_permissions(g.get("IpPermissionsEgress", [])),
                tags=_tags(g),
            )
        )

    for a in _pages(ec2, "describe_network_acls", "NetworkAcls", Filters=in_vpcs):
        inv.acls.append(
            NetworkAcl(
                id=a["NetworkAclId"],
                vpc_id=a["VpcId"],
                is_default=a.get("IsDefault", False),
                subnet_ids=[x["SubnetId"] for x in a.get("Associations", [])],
                entries=[_acl_entry(e) for e in a.get("Entries", [])],
                tags=_tags(a),
            )
        )

    for t in _pages(ec2, "describe_route_tables", "RouteTables", Filters=in_vpcs):
        links = t.get("Associations", [])
        inv.route_tables.append(
            RouteTable(
                id=t["RouteTableId"],
                vpc_id=t["VpcId"],
                main=any(x.get("Main") for x in links),
                subnet_ids=[x["SubnetId"] for x in links if x.get("SubnetId")],
                routes=[
                    Route(r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock") or "", _route_target(r))
                    for r in t.get("Routes", [])
                    if r.get("State", "active") == "active"
                ],
                tags=_tags(t),
            )
        )

    for p in _pages(ec2, "describe_vpc_peering_connections", "VpcPeeringConnections"):
        if p["Status"]["Code"] != "active":
            continue
        ends = p["RequesterVpcInfo"]["VpcId"], p["AccepterVpcInfo"]["VpcId"]
        if set(ends) & set(vpc_ids):
            inv.peerings.append(Peering(p["VpcPeeringConnectionId"], *ends))

    for log in _pages(ec2, "describe_flow_logs", "FlowLogs", Filter=[{"Name": "resource-id", "Values": vpc_ids}]):
        vpc = inv.vpc(log["ResourceId"])
        if vpc and log.get("FlowLogStatus", "ACTIVE") == "ACTIVE":
            vpc.flow_log_traffic.append(log.get("TrafficType", ""))

    live = in_vpcs + [{"Name": "instance-state-name", "Values": LIVE_STATES}]
    for r in _pages(ec2, "describe_instances", "Reservations", Filters=live):
        for i in r["Instances"]:
            inv.instances.append(
                Instance(
                    id=i["InstanceId"],
                    vpc_id=i.get("VpcId"),
                    subnet_id=i.get("SubnetId"),
                    state=i["State"]["Name"],
                    public_ip=i.get("PublicIpAddress"),
                    group_ids=_primary_groups(i),
                    imds_tokens=(i.get("MetadataOptions") or {}).get("HttpTokens"),
                    tags=_tags(i),
                )
            )
    return inv


def collect_all(session: boto3.Session, tag: tuple[str, str] | None = None) -> list[Inventory]:
    regions = [r["RegionName"] for r in session.client("ec2").describe_regions()["Regions"]]
    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(lambda region: collect(session, region, tag), sorted(regions)))
