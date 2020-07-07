---
description: Relational Database Service (RDS) Instance
---

# RDS Instance

#### Resource Type

`AWS.RDS.Instance`

#### Resource ID Format

For RDS Instances, the resource ID is the ARN.

`arn:aws:rds:us-west-2:123456789012:db:example-db`

#### Background

AWS RDS instances are managed EC2 instances that run relational databases.

#### Fields

| Field                | Type   | Description                                                                   |
| :------------------- | :----- | :---------------------------------------------------------------------------- |
| `DBParameterGroups`  | `List` | The parameter groups the instance belongs to                                  |
| `SnapshotAttributes` | `List` | A list of each snapshot for the instance, and the attributes of that snapshot |

```javascript
{
    "AccountId": "123456789012",
    "AllocatedStorage": 20,
    "Arn": "arn:aws:rds:us-west-2:123456789012:db:example-db",
    "AssociatedRoles": null,
    "AutoMinorVersionUpgrade": true,
    "AvailabilityZone": "us-west-2a",
    "BackupRetentionPeriod": 7,
    "CACertificateIdentifier": "rds-ca-2015",
    "CharacterSetName": null,
    "CopyTagsToSnapshot": true,
    "DBClusterIdentifier": null,
    "DBInstanceClass": "db.t2.micro",
    "DBInstanceStatus": "available",
    "DBParameterGroups": [
        {
            "DBParameterGroupName": "default.mysql5.7",
            "ParameterApplyStatus": "in-sync"
        }
    ],
    "DBSecurityGroups": null,
    "DBSubnetGroup": {
        "DBSubnetGroupArn": null,
        "DBSubnetGroupDescription": "default",
        "DBSubnetGroupName": "default",
        "SubnetGroupStatus": "Complete",
        "Subnets": [
            {
                "SubnetAvailabilityZone": {
                    "Name": "us-west-2b"
                },
                "SubnetIdentifier": "subnet-1",
                "SubnetStatus": "Active"
            },
            {
                "SubnetAvailabilityZone": {
                    "Name": "us-west-2d"
                },
                "SubnetIdentifier": "subnet-2",
                "SubnetStatus": "Active"
            }
        ],
        "VpcId": "vpc-1"
    },
    "DbInstancePort": 0,
    "DbiResourceId": "db-1111",
    "DeletionProtection": false,
    "DomainMemberships": null,
    "EnabledCloudwatchLogsExports": null,
    "Endpoint": {
        "Address": "example-db.1111.us-west-2.rds.amazonaws.com",
        "HostedZoneId": "AAAA",
        "Port": 1234
    },
    "Engine": "mysql",
    "EngineVersion": "5.7.22",
    "EnhancedMonitoringResourceArn": null,
    "IAMDatabaseAuthenticationEnabled": false,
    "Id": "example-db",
    "Iops": null,
    "KmsKeyId": null,
    "LatestRestorableTime": "2019-01-01T00:00:00Z",
    "LicenseModel": "general-public-license",
    "ListenerEndpoint": null,
    "MasterUsername": "superuser",
    "MaxAllocatedStorage": null,
    "MonitoringInterval": 0,
    "MonitoringRoleArn": null,
    "MultiAZ": false,
    "Name": "db_1",
    "OptionGroupMemberships": [
        {
            "OptionGroupName": "default:mysql-5-7",
            "Status": "in-sync"
        }
    ],
    "PendingModifiedValues": {
        "AllocatedStorage": null,
        "BackupRetentionPeriod": null,
        "CACertificateIdentifier": null,
        "DBInstanceClass": null,
        "DBInstanceIdentifier": null,
        "DBSubnetGroupName": null,
        "EngineVersion": null,
        "Iops": null,
        "LicenseModel": null,
        "MasterUserPassword": null,
        "MultiAZ": null,
        "PendingCloudwatchLogsExports": null,
        "Port": null,
        "ProcessorFeatures": null,
        "StorageType": null
    },
    "PerformanceInsightsEnabled": false,
    "PerformanceInsightsKMSKeyId": null,
    "PerformanceInsightsRetentionPeriod": null,
    "PreferredBackupWindow": "07:31-08:01",
    "PreferredMaintenanceWindow": "thu:12:02-thu:12:32",
    "ProcessorFeatures": null,
    "PromotionTier": null,
    "PubliclyAccessible": true,
    "ReadReplicaDBClusterIdentifiers": null,
    "ReadReplicaDBInstanceIdentifiers": null,
    "ReadReplicaSourceDBInstanceIdentifier": null,
    "Region": "us-west-2",
    "ResourceId": "arn:aws:rds:us-west-2:123456789012:db:example-db",
    "ResourceType": "AWS.RDS.Instance",
    "SecondaryAvailabilityZone": null,
    "SnapshotAttributes": [
        {
            "DBSnapshotAttributes": [
                {
                    "AttributeName": "restore",
                    "AttributeValues": null
                }
            ],
            "DBSnapshotIdentifier": "snapshot-1"
        },
        {
            "DBSnapshotAttributes": [
                {
                    "AttributeName": "restore",
                    "AttributeValues": [
                        "all"
                    ]
                }
            ],
            "DBSnapshotIdentifier": "public-snapshot"
        }
    ],
    "StatusInfos": null,
    "StorageEncrypted": false,
    "StorageType": "gp2",
    "Tags": {
        "workload-type": "other"
    },
    "TdeCredentialArn": null,
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "Timezone": null,
    "VpcSecurityGroups": [
        {
            "Status": "active",
            "VpcSecurityGroupId": "sg-1"
        }
    ]
}
```
