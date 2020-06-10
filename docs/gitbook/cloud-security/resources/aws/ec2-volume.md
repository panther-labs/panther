---
description: Elastic Compute Cloud (EC2) Volume
---

# EC2 Volume

#### Resource Type

`AWS.EC2.Volume`

#### Resource ID Format

For EC2 Volumes, the resource ID is the ARN.

`arn:aws:ec2:us-west-2:123456789012:volume/vol-1`

#### Background

This resource represents a snapshot of an AWS EC2 Volume.

#### Fields

| Field         | Type     | Description                                                                                                                                                                  |
| :------------ | :------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Attachments` | `List`   | What devices this volume is attached to                                                                                                                                      |
| `Encrypted`   | `Bool`   | Indicates whether the volume is encrypted                                                                                                                                    |
| `KmsKeyId`    | `String` | The Amazon Resource Name \(ARN\) of the AWS Key Management Service \(AWS KMS\) customer master key \(CMK\) that was used to protect the volume encryption key for the volume |
| `State`       | `String` | The volume state`creating | available | in-use | deleting | deleted | error`                                                                                                 |

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:ec2:us-west-2:123456789012:volume/vol-1",
    "Attachments": [
        {
            "AttachTime": "2019-01-01T00:00:00Z",
            "DeleteOnTermination": false,
            "Device": "/dev/sdf",
            "InstanceId": "i-1",
            "State": "attached",
            "VolumeId": "vol-1"
        }
    ],
    "AvailabilityZone": "us-west-2b",
    "Encrypted": false,
    "Id": "vol-1",
    "Iops": 100,
    "KmsKeyId": null,
    "Region": "us-west-2",
    "ResourceId": "arn:aws:ec2:us-west-2:123456789012:volume/vol-1",
    "ResourceType": "AWS.EC2.Volume",
    "Size": 1,
    "SnapshotId": null,
    "Snapshots": [
        null,
        {
            "CreateVolumePermissions": null,
            "DataEncryptionKeyId": null,
            "Description": "volume snapshot",
            "Encrypted": false,
            "KmsKeyId": null,
            "OwnerAlias": null,
            "OwnerId": "123456789012",
            "Progress": "100%",
            "SnapshotId": "snap-1",
            "StartTime": "2019-01-01T00:00:00.000Z",
            "State": "completed",
            "StateMessage": null,
            "Tags": null,
            "VolumeId": "vol-1",
            "VolumeSize": 1
        }
    ],
    "State": "in-use",
    "Tags": {
        "Key1": "Value1",
        "Key2": "Value2"
    },
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "VolumeType": "gp2"
}
```
