---
description: Elastic Compute Cloud (EC2) Virtual Private Cloud (VPC) Network ACL
---

# EC2 Network ACL

#### Resource Type

`AWS.EC2.NetworkACL`

#### Resource ID Format

For EC2 Network ACLs, the resource ID is the ARN.

`arn:aws:ec2:us-west-2:123456789012:network-acl/acl-1`

#### Background

This resource represents a snapshot of an AWS EC2 VPC NetworkACL.

#### Fields

| Field       | Type   | Description                                                                |
| :---------- | :----- | :------------------------------------------------------------------------- |
| `Entries`   | `List` | Individual Network ACL rules to allow or block traffic                     |
| `IsDefault` | `Bool` | Whether this Network ACL is the default Network ACL for its associated VPC |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:ec2:us-west-2:123456789012:network-acl/acl-1",
    "Associations": [
        {
            "NetworkAclAssociationId": "aclassoc-1",
            "NetworkAclId": "acl-1",
            "SubnetId": "subnet-1"
        }
    ],
    "Entries": [
        {
            "CidrBlock": "0.0.0.0/0",
            "Egress": true,
            "IcmpTypeCode": null,
            "Ipv6CidrBlock": null,
            "PortRange": {
                "From": 80,
                "To": 80
            },
            "Protocol": "6",
            "RuleAction": "allow",
            "RuleNumber": 100
        },
        {
            "CidrBlock": "10.0.0.0/20",
            "Egress": false,
            "IcmpTypeCode": null,
            "Ipv6CidrBlock": null,
            "PortRange": null,
            "Protocol": "-1",
            "RuleAction": "allow",
            "RuleNumber": 110
        }
    ],
    "Id": "acl-1",
    "IsDefault": false,
    "OwnerId": "123456789012",
    "Region": "us-west-2",
    "ResourceId": "arn:aws:ec2:us-west-2:123456789012:network-acl/acl-1",
    "ResourceType": "AWS.EC2.NetworkACL",
    "Tags": {
        "Name": "PrivateSubnetAcl",
        "aws:cloudformation:logical-id": "PrivateSubnetAcl",
        "aws:cloudformation:stack-id": "arn:aws:cloudformation:us-west-2:123456789012:stack/vpc/1",
        "aws:cloudformation:stack-name": "vpc"
    },
    "TimeCreated": null,
    "VpcId": "vpc-1"
}
```
