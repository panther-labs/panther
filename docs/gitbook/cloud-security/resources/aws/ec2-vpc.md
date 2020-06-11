---
description: Elastic Compute Cloud (EC2) Virtual Private Cloud (VPC)
---

# EC2 VPC

#### Resource Type

`AWS.EC2.VPC`

#### Resource ID Format

For EC2 VPCs, the resource ID is the ARN.

`arn:aws:ec2:us-west-2:123456789012:vpc/vpc-1`

#### Background

This resource represents a snapshot of an AWS EC2 VPC.

#### Fields

| Field                 | Type     | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| :-------------------- | :------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CidrBlock`           | `IP`     | The IP range of the VPC                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `NetworkAcls`         | `List`   | Indicates what network ACLs are set, which act as a basic firewall for the VPC. See the [AWS user documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html) for more details                                                                                                                                                                                                                                                                                                                                              |
| `RouteTables`         | `List`   | Route tables are configured, which act as basic routing tables for the VPC. See the [AWS user documentation](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html) for more details.                                                                                                                                                                                                                                                                                                                                                 |
| `VpcId`               | `String` | The unique identifier of the VPC                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `SecurityGroups`      | `List`   | Security groups configured for this VPC, which act as firewalls for instances in the VPC. See the [AWS user documentation](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html) for more details                                                                                                                                                                                                                                                                                                                                  |
| `StaleSecurityGroups` | `List`   | Security groups in a VPC that are 'stale', meaning the corresponding security group or VPC peering connection has been deleted. Note that the example below lists a stale security group that is not listed in `SecurityGroups`, in practice this will not be the case. All security groups listed in `StaleSecurityGroups` will also be present in `SecurityGroups`. See the [AWS documentation](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-security-groups.html#vpc-peering-stale-groups) for more details on stale security groups. |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:ec2:eu-west-3:123456789012:vpc/vpc-1",
    "CidrBlock": "10.0.0.0/16",
    "CidrBlockAssociationSet": [
        {
            "AssociationId": "vpc-cidr-assoc-1",
            "CidrBlock": "10.0.0.0/16",
            "CidrBlockState": {
                "State": "associated",
                "StatusMessage": null
            }
        }
    ],
    "DhcpOptionsId": "dopt-1",
    "FlowLogs": null,
    "Id": "vpc-1",
    "InstanceTenancy": "default",
    "Ipv6CidrBlockAssociationSet": null,
    "IsDefault": true,
    "NetworkAcls": [
        {
            "Associations": [
                {
                    "NetworkAclAssociationId": "aclassoc-1",
                    "NetworkAclId": "acl-1",
                    "SubnetId": "subnet-1"
                },
                {
                    "NetworkAclAssociationId": "aclassoc-2",
                    "NetworkAclId": "acl-1",
                    "SubnetId": "subnet-2"
                }
            ],
            "Entries": [
                {
                    "CidrBlock": "0.0.0.0/0",
                    "Egress": true,
                    "IcmpTypeCode": null,
                    "Ipv6CidrBlock": null,
                    "PortRange": null,
                    "Protocol": "-1",
                    "RuleAction": "allow",
                    "RuleNumber": 100
                }
            ],
            "IsDefault": true,
            "NetworkAclId": "acl-1",
            "OwnerId": "123456789012",
            "Tags": null,
            "VpcId": "vpc-1"
        }
    ],
    "OwnerId": "123456789012",
    "Region": "eu-west-3",
    "ResourceId": "arn:aws:ec2:eu-west-3:123456789012:vpc/vpc-1",
    "ResourceType": "AWS.EC2.VPC",
    "RouteTables": null,
    "SecurityGroups": [
        {
            "Description": "default VPC security group",
            "GroupId": "sg-1",
            "GroupName": "default",
            "IpPermissions": [
                {
                    "FromPort": null,
                    "IpProtocol": "-1",
                    "IpRanges": null,
                    "Ipv6Ranges": null,
                    "PrefixListIds": null,
                    "ToPort": null,
                    "UserIdGroupPairs": [
                        {
                            "Description": null,
                            "GroupId": "sg-1",
                            "GroupName": null,
                            "PeeringStatus": null,
                            "UserId": "123456789012",
                            "VpcId": null,
                            "VpcPeeringConnectionId": null
                        }
                    ]
                }
            ],
            "IpPermissionsEgress": [
                {
                    "FromPort": null,
                    "IpProtocol": "-1",
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                            "Description": null
                        }
                    ],
                    "Ipv6Ranges": null,
                    "PrefixListIds": null,
                    "ToPort": null,
                    "UserIdGroupPairs": null
                }
            ],
            "OwnerId": "123456789012",
            "Tags": null,
            "VpcId": "vpc-1"
        }
    ],
    "StaleSecurityGroups": null,
    "State": "available",
    "Tags": null,
    "TimeCreated": null
}
```
