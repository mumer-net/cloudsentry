"""The live collector against moto's fake EC2 API."""

import boto3
import pytest
from moto import mock_aws

from cloudsentry import collect_aws, rules

TAG = ("Project", "cloudsentry")


@pytest.fixture
def session(monkeypatch):
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(key, "testing")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")


def tagged_vpc(ec2, cidr: str, tagged: bool = True) -> str:
    tags = [{"ResourceType": "vpc", "Tags": [{"Key": "Project", "Value": "cloudsentry"}]}] if tagged else []
    return ec2.create_vpc(CidrBlock=cidr, TagSpecifications=tags)["Vpc"]["VpcId"]


@pytest.fixture
def lab(session):
    ec2 = session.client("ec2")
    a = tagged_vpc(ec2, "10.20.0.0/16")
    b = tagged_vpc(ec2, "10.30.0.0/16")
    other = tagged_vpc(ec2, "10.99.0.0/16", tagged=False)
    subnet = ec2.create_subnet(VpcId=a, CidrBlock="10.20.1.0/24")["Subnet"]["SubnetId"]

    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=a)
    public = ec2.create_route_table(VpcId=a)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=public, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=public, SubnetId=subnet)

    acl = ec2.create_network_acl(VpcId=a)["NetworkAcl"]["NetworkAclId"]
    ec2.create_network_acl_entry(
        NetworkAclId=acl,
        RuleNumber=90,
        Protocol="6",
        RuleAction="deny",
        Egress=False,
        CidrBlock="0.0.0.0/0",
        PortRange={"From": 22, "To": 22},
    )
    ec2.create_network_acl_entry(
        NetworkAclId=acl, RuleNumber=100, Protocol="-1", RuleAction="allow", Egress=False, CidrBlock="0.0.0.0/0"
    )
    default_acl = ec2.describe_network_acls(
        Filters=[{"Name": "vpc-id", "Values": [a]}, {"Name": "default", "Values": ["true"]}]
    )
    association = default_acl["NetworkAcls"][0]["Associations"][0]["NetworkAclAssociationId"]
    ec2.replace_network_acl_association(AssociationId=association, NetworkAclId=acl)

    ssh = ec2.create_security_group(GroupName="ssh-world", Description="test", VpcId=a)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=ssh,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )

    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        InstanceType="t4g.micro",
        MetadataOptions={"HttpTokens": "optional"},
        NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet, "Groups": [ssh], "AssociatePublicIpAddress": True}],
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web"}]}],
    )

    pcx = ec2.create_vpc_peering_connection(VpcId=a, PeerVpcId=b)["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx)
    private = ec2.create_route_table(VpcId=a)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=private, DestinationCidrBlock="10.30.0.0/16", VpcPeeringConnectionId=pcx)

    session.client("s3").create_bucket(Bucket="flow-logs")
    ec2.create_flow_logs(
        ResourceIds=[a],
        ResourceType="VPC",
        TrafficType="REJECT",
        LogDestinationType="s3",
        LogDestination="arn:aws:s3:::flow-logs",
    )
    return {
        "a": a,
        "b": b,
        "other": other,
        "subnet": subnet,
        "igw": igw,
        "acl": acl,
        "ssh": ssh,
        "pcx": pcx,
        "private": private,
    }


def test_only_tagged_vpcs_are_collected(session, lab):
    inv = collect_aws.collect(session, "us-east-1", TAG)
    assert {v.id for v in inv.vpcs} == {lab["a"], lab["b"]}
    assert all(g.vpc_id in (lab["a"], lab["b"]) for g in inv.groups)


def test_instance_details(session, lab):
    inv = collect_aws.collect(session, "us-east-1", TAG)
    [instance] = inv.instances
    assert instance.name == "web"
    assert instance.public_ip
    assert instance.group_ids == [lab["ssh"]]
    assert instance.imds_tokens == "optional"
    assert inv.subnets[instance.subnet_id] == lab["a"]


def test_routes_and_network_acls(session, lab):
    inv = collect_aws.collect(session, "us-east-1", TAG)
    table = inv.route_table_for(lab["subnet"])
    assert (lab["igw"]) in [r.target for r in table.routes if r.destination == "0.0.0.0/0"]
    acl = inv.acl_for(lab["subnet"])
    assert acl.id == lab["acl"]
    assert [(e.number, e.allow, e.protocol) for e in acl.rules(egress=False)][:2] == [
        (90, False, "tcp"),
        (100, True, "all"),
    ]


def test_findings_from_the_live_collector(session, lab):
    inv = collect_aws.collect(session, "us-east-1", TAG)
    found = {(f.control, f.resource) for f in rules.run(inv)}
    assert ("CIS 5.3", lab["ssh"]) in found
    assert ("CIS 5.6", lab["private"]) in found
    assert ("CIS 3.7", lab["b"]) in found
    assert ("CIS 3.7", lab["a"]) not in found
    assert sum(f.control == "CIS 5.7" for f in rules.run(inv)) == 1
    # The custom ACL denies 22 before its allow-all rule, so only 3389 is open.
    [acl] = [f for f in rules.run(inv) if f.resource == lab["acl"]]
    assert acl.detail == "inbound from 0.0.0.0/0 allowed on port 3389"


def test_all_regions(session, lab):
    session.client("ec2", region_name="eu-west-1").create_vpc(
        CidrBlock="10.40.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Project", "Value": "cloudsentry"}]}],
    )
    inventories = collect_aws.collect_all(session, TAG)
    by_region = {inv.region: len(inv.vpcs) for inv in inventories}
    assert by_region["us-east-1"] == 2
    assert by_region["eu-west-1"] == 1
