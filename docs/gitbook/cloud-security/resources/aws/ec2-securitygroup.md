---
description: Elastic Compute Cloud (EC2) Virtual Private Cloud (VPC) SecurityGroup
---

# EC2 SecurityGroup

#### Resource Type

`AWS.EC2.SecurityGroup`

#### Resource ID Format

For EC2 Security Groups, the resource ID is the ARN.

`arn:aws:ec2:us-west-2:123456789012:security-group/sg-1`

#### Background

This resource represents a snapshot of an AWS EC2 VPC SecurityGroup.

#### Fields

| Field                 | Type   | Description                        |
| :-------------------- | :----- | :--------------------------------- |
| `IpPermissions`       | `List` | Inbound IP permissions             |
| `IpPermissionsEgress` | `List` | Outbound \(egress\) IP permissions |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:ec2:ap-northeast-2:123456789012:security-group/sg-1",
    "Description": "default VPC security group",
    "Id": "sg-1",
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
    "Name": "default",
    "OwnerId": "123456789012",
    "Region": "ap-northeast-2",
    "ResourceId": "arn:aws:ec2:ap-northeast-2:123456789012:security-group/sg-1",
    "ResourceType": "AWS.EC2.SecurityGroup",
    "Tags": null,
    "TimeCreated": null,
    "VpcId": "vpc-1"
}
```
