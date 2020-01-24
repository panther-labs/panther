# EC2 Instance

#### Resource Type

`AWS.EC2.Instance`

#### Resource ID Format

For EC2 Instances, the resource ID is the ARN.

`arn:aws:ec2:us-west-2:123456789012:instance/i-1`

#### Background

This resource represents a snapshot of an AWS EC2 Instance.

#### Fields

| Field                 | Type   | Description                                                     |
| :-------------------- | :----- | :-------------------------------------------------------------- |
| `BlockDeviceMappings` | `List` | Lists what block devices are attached                           |
| `NetworkInterfaces`   | `Map`  | Detailed information about the instance's network configuration |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "AmiLaunchIndex": 0,
    "Architecture": "x86_64",
    "Arn": "arn:aws:ec2:us-west-2:123456789012:instance/i-1",
    "BlockDeviceMappings": [
        {
            "DeviceName": "/dev/xvda",
            "Ebs": {
                "AttachTime": "2019-01-01T00:00:00Z",
                "DeleteOnTermination": true,
                "Status": "attached",
                "VolumeId": "vol-1"
            }
        }
    ],
    "CapacityReservationId": null,
    "CapacityReservationSpecification": {
        "CapacityReservationPreference": "open",
        "CapacityReservationTarget": null
    },
    "ClientToken": null,
    "CpuOptions": {
        "CoreCount": 1,
        "ThreadsPerCore": 1
    },
    "EbsOptimized": false,
    "ElasticGpuAssociations": null,
    "ElasticInferenceAcceleratorAssociations": null,
    "EnaSupport": true,
    "HibernationOptions": {
        "Configured": false
    },
    "Hypervisor": "xen",
    "IamInstanceProfile": null,
    "Id": "i-1",
    "ImageId": "ami-1",
    "InstanceLifecycle": null,
    "InstanceType": "t2.micro",
    "KernelId": null,
    "KeyName": "ec2-instance-key-pair",
    "Licenses": null,
    "Monitoring": {
        "State": "disabled"
    },
    "NetworkInterfaces": [
        {
            "Association": {
                "IpOwnerId": "amazon",
                "PublicDnsName": "ec2-111-111-111-111.us-west-2.compute.amazonaws.com",
                "PublicIp": "111.111.111.111"
            },
            "Attachment": {
                "AttachTime": "2019-01-01T00:00:00Z",
                "AttachmentId": "eni-attach-1",
                "DeleteOnTermination": true,
                "DeviceIndex": 0,
                "Status": "attached"
            },
            "Description": null,
            "Groups": [
                {
                    "GroupId": "sg-1",
                    "GroupName": "launch-wizard-1"
                }
            ],
            "InterfaceType": "interface",
            "Ipv6Addresses": null,
            "MacAddress": "00:00:de:ad:be:ef",
            "NetworkInterfaceId": "eni-1",
            "OwnerId": "123456789012",
            "PrivateDnsName": "ip-10-10-10-10.us-west-2.compute.internal",
            "PrivateIpAddress": "10.10.10.10",
            "PrivateIpAddresses": [
                {
                    "Association": {
                        "IpOwnerId": "amazon",
                        "PublicDnsName": "ec2-111-111-111-111.us-west-2.compute.amazonaws.com",
                        "PublicIp": "111.111.111.111"
                    },
                    "Primary": true,
                    "PrivateDnsName": "ip-10-10-10-10.us-west-2.compute.internal",
                    "PrivateIpAddress": "10.10.10.10"
                }
            ],
            "SourceDestCheck": true,
            "Status": "in-use",
            "SubnetId": "subnet-1",
            "VpcId": "vpc-1"
        }
    ],
    "Placement": {
        "Affinity": null,
        "AvailabilityZone": "us-west-2b",
        "GroupName": null,
        "HostId": null,
        "PartitionNumber": null,
        "SpreadDomain": null,
        "Tenancy": "default"
    },
    "Platform": null,
    "PrivateDnsName": "ip-10-10-10-10.us-west-2.compute.internal",
    "PrivateIpAddress": "10.10.10.10",
    "ProductCodes": null,
    "PublicDnsName": "ec2-111-111-111-111.us-west-2.compute.amazonaws.com",
    "PublicIpAddress": "111.111.111.111",
    "RamdiskId": null,
    "Region": "us-west-2",
    "ResourceId": "arn:aws:ec2:us-west-2:123456789012:instance/i-1",
    "ResourceType": "AWS.EC2.Instance",
    "RootDeviceName": "/dev/xvda",
    "RootDeviceType": "ebs",
    "SecurityGroups": [
        {
            "GroupId": "sg-1",
            "GroupName": "launch-wizard-1"
        }
    ],
    "SourceDestCheck": true,
    "SpotInstanceRequestId": null,
    "SriovNetSupport": null,
    "State": {
        "Code": 16,
        "Name": "running"
    },
    "StateReason": null,
    "StateTransitionReason": null,
    "SubnetId": "subnet-1",
    "Tags": {
        "Key1": "Value1"
    },
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "VirtualizationType": "hvm",
    "VpcId": "vpc-1"
}
```
