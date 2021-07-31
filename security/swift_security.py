"""Class for SWIFT specific security"""
import boto3
from aws_cdk import (
    core,
    aws_ec2 as _ec2,
)
from utilities.swift_components import SwiftComponents
from security.generic_security import GenericSecurity


class SWIFTSecurity(GenericSecurity):
    """Class for SWIFT specific security, inherit from generic security"""
    # pylint: disable=too-many-arguments
    def __init__(self, scope: core.Construct, cid: str,
                 vpc: _ec2.Vpc,
                 swift_ip_range: str = "149.134.0.0/16",
                 hsm_ip: str = "10.20.1.10/32",
                 workstation_ip_range: str = "10.1.0.0/16", **kwargs) -> None:
        super().__init__(scope, cid, vpc, **kwargs)
        self._swift_ip_range = swift_ip_range
        self._hsm_ip = hsm_ip
        self._workstation_ip_range = workstation_ip_range
        self.create_security_group("VPCEndpointSG")

    def enforce_security_groups_rules(self) -> None:
        """enforcing security group rule. ie creating security group rule """
        sildirlink_sg = self.get_security_group(SwiftComponents.SILDIRLINK + "SG")

        boto = boto3.client("ec2")
        prefix_lists = boto.describe_prefix_lists(
            Filters=[{"Name": "prefix-list-name", "Values": ["com.amazonaws.*.s3"]}])
        s3_prefix_list = prefix_lists["PrefixLists"][0]["PrefixListId"]

        self.add_security_group_rule(SwiftComponents.SILDIRLINK + "SG", protocol=_ec2.Protocol.TCP,
                                     cidr_range=self._workstation_ip_range,
                                     from_port=2443, to_port=2443, is_ingress=True,
                                     description="SWP Web GUI Interface Ingress from workstation"
                                     )
        self.add_security_group_rule(SwiftComponents.SILDIRLINK + "SG", protocol=_ec2.Protocol.TCP,
                                     prefix_list=s3_prefix_list,
                                     from_port=443, to_port=443, is_ingress=False,
                                     description="Egress to S3 VPC Gateway Endpoint"
                                     )
        self.add_security_group_rule(SwiftComponents.SILDIRLINK + "SG", protocol=_ec2.Protocol.ALL,
                                     cidr_range=self._swift_ip_range,
                                     from_port=0, to_port=65535, is_ingress=False,
                                     description="To SWIFT via VGW and VPN"
                                     )
        self.add_security_group_rule(SwiftComponents.SILDIRLINK + "SG", protocol=_ec2.Protocol.TCP,
                                     cidr_range=self._hsm_ip,
                                     from_port=1792, to_port=1792, is_ingress=False,
                                     description="To HSM via VGW"
                                     )
        self.add_security_group_rule(SwiftComponents.SILDIRLINK + "SG", protocol=_ec2.Protocol.TCP,
                                     cidr_range=self._hsm_ip,
                                     from_port=22, to_port=22, is_ingress=False,
                                     description="To HSM (SSH) via VGW"
                                     )
        self.add_security_group_rule(SwiftComponents.SILDIRLINK + "SG", protocol=_ec2.Protocol.TCP,
                                     cidr_range=self._hsm_ip,
                                     from_port=48321, to_port=48321, is_ingress=False,
                                     description="TO HSM (Remote PED) via VGW "
                                     )

    def create_nacls(self) -> None:
        """creating nacl and rules"""
        selection_sildirlink = _ec2.SubnetSelection(subnet_group_name=SwiftComponents.SILDIRLINK)

        self.create_nacl(cid=SwiftComponents.SILDIRLINK + "NACL", name=SwiftComponents.SILDIRLINK + "NACL",
                         description="NACL for SILDIRLINK Subnet",
                         subnet_selection=selection_sildirlink)

        self.add_nacl_entry(cid=SwiftComponents.SILDIRLINK + "NACL",
                            nacl_id="SILDIRLINKNACLEntry1",
                            cidr=_ec2.AclCidr.any_ipv4(),
                            rule_number=100,
                            traffic=_ec2.AclTraffic.all_traffic(),
                            direction=_ec2.TrafficDirection.EGRESS)
        self.add_nacl_entry(cid=SwiftComponents.SILDIRLINK + "NACL",
                            nacl_id="SILDIRLINKNACLEntry2",
                            cidr=_ec2.AclCidr.any_ipv4(),
                            rule_number=100,
                            traffic=_ec2.AclTraffic.all_traffic(),
                            direction=_ec2.TrafficDirection.INGRESS)

