"""main swift stack"""
from aws_cdk import (
    core,
    aws_ec2 as _ec2
)
from cdk_ec2_key_pair import KeyPair

from cmk.generic_cmk import GenericCMK
from network.generic_network import GenericNetwork
from network.swift_vpc_endpoints import SwiftVPCEndpoints
from security.swift_security import SWIFTSecurity
from swift_iam_role.swift_iam_role import SwiftIAMRole
from swift_sildirlink.swift_sildirlink import SwiftSILDIRLINK
from utilities.swift_components import SwiftComponents


class SwiftMain(core.Stack):
    """main swift stack, for creating nested stack"""

    # pylint: disable=too-many-locals
    def __init__(self, scope: core.Construct, cid: str, **kwargs) -> None:
        super().__init__(scope, cid, **kwargs)

        # Create CMK used by the entire stack
        cmk_stack = GenericCMK(self, "SwiftConnectivityCMK")
        workload_key = cmk_stack.get_cmk()

        # Create networking constructs
        network_stack = GenericNetwork(
            self, "SwiftConnectivityVPC", cidr_range=self.node.try_get_context("vpc_cidr"))
        network_stack.set_vgw(True)
        network_stack.add_isolated_subnets(SwiftComponents.SILDIRLINK)
        network_stack.set_vgw_propagation_subnet(
            _ec2.SubnetSelection(subnet_name=SwiftComponents.SILDIRLINK))
        network_stack.generate()

        # Create security constructs ( IAM Role, SGs, SG Rules, NACLs )
        security_stack = SWIFTSecurity(
            self, "SwiftConnectivitySecurity", vpc=network_stack.get_vpc(),
            swift_ip_range=self.node.try_get_context("swift_ip_range"),
            hsm_ip=self.node.try_get_context("hsm_ip"),
            workstation_ip_range=self.node.try_get_context("workstation_ip_range")
        )

        ops_key_pair: KeyPair = \
            KeyPair(self, "OperatorKeyPair2", name="OperatorKeyPair2",
                    region=self.region,
                    description="KeyPair for the systems operator, just in case."
                    )

        # Create SILDIRLINK instance , should deploy
        # the instance to the AZ that's according to the provided IP
        sildirlink_ami = self.node.try_get_context("sildirlink_ami")
        if not sildirlink_ami:
            sildirlink_ami = None
        sil_dirlinks = []
        for i in range(1, 3):
            sil_dirlink = SwiftSILDIRLINK(
                self, cid=SwiftComponents.SILDIRLINK + str(i),
                network=network_stack, security=security_stack,
                workload_key=workload_key, ops_key=ops_key_pair,
                private_ip=self.node.try_get_context("sildirlink" + str(i) + "_ip"),
                ami_id=sildirlink_ami,
                vpc_subnets=_ec2.SubnetSelection(
                    availability_zones=[self.availability_zones[i - 1]],
                    subnet_group_name=SwiftComponents.SILDIRLINK)
            )
            sil_dirlinks.append(sil_dirlink.get_instance_id())

        # enforce Security group and rule and nacls after the components are created
        security_stack.enforce_security_groups_rules()
        security_stack.create_nacls()

        # Create VPC endpoints and VPC Endpoints policy
        SwiftVPCEndpoints(self, "VPCEndPointStack",
                          application_names=[SwiftComponents.SILDIRLINK],
                          instance_roles_map=security_stack.get_instance_roles(),
                          endpoint_sg=security_stack.get_security_group("VPCEndpointSG"),
                          vpc=network_stack.get_vpc(),
                          instance_ids={SwiftComponents.SILDIRLINK: sil_dirlinks}
                          )
        for count, value in enumerate(sil_dirlinks):
            core.CfnOutput(self, "SILDIRLINK" + str(count + 1) + "InstanceID", value=value)
        core.CfnOutput(self, "VPCID", value=network_stack.get_vpc().vpc_id)

        # Create sample role for accessing the components created
        if self.node.try_get_context("create_sample_iam_role") == "true":
            SwiftIAMRole(self, "IAMRole",
                         instance_ids=sil_dirlinks
                         )
