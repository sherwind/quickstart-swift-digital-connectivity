"""SILDIRLINK Instance"""
from aws_cdk import (
    core,
    aws_kms as _kms,
    aws_ec2 as _ec2,
)
from cdk_ec2_key_pair import KeyPair

from base_host_group.host_group import HostGroup
from network.generic_network import GenericNetwork
from security.generic_security import GenericSecurity
from utilities.swift_components import SwiftComponents


class SwiftSILDIRLINK(HostGroup):
    """SILDIRLINK Instance"""

    # pylint: disable=too-many-arguments
    def __init__(self, scope: core.Construct, cid: str,
                 network: GenericNetwork,
                 security: GenericSecurity,
                 workload_key: _kms.Key,
                 ops_key: KeyPair,
                 vpc_subnets: _ec2.SubnetSelection,
                 ami_id: str = None,
                 private_ip: str = None,
                 **kwargs) -> None:
        super().__init__(scope, cid=cid,
                         component=SwiftComponents.SILDIRLINK,
                         network=network,
                         security=security,
                         workload_key=workload_key,
                         ops_key=ops_key,
                         vpc_subnets=vpc_subnets,
                         ami_id=ami_id,
                         private_ip=private_ip,
                         **kwargs
                         )
