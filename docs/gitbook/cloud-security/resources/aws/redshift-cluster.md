# Redshift Cluster

#### Resource Type

`AWS.Redshift.Cluster`

#### Resource ID Format

For Redshift Clusters, the resource ID is the ARN.

`arn:aws:redshift:us-west-2:123456789012:cluster:example-cluster`

#### Background

An Amazon Redshift data warehouse is a collection of computing resources called nodes, which are organized into a group called a cluster. Each cluster runs an Amazon Redshift engine and contains one or more databases.

#### Fields

The fields below include a [Redshift Cluster](https://docs.aws.amazon.com/redshift/latest/APIReference/API_Cluster.html) with its Logging Status \(detailed below\).

| Field                        | Type     | Description                                               |
| :--------------------------- | :------- | :-------------------------------------------------------- |
| `BucketName`                 | `String` | The name of the S3 bucket where the log files are stored. |
| `LastFailureMessage`         | `String` | The message indicating that logs failed to be delivered.  |
| `LastFailureTime`            | `Time`   | The last time when logs failed to be delivered.           |
| `LastSuccessfulDeliveryTime` | `Time`   | The last time that logs were delivered.                   |
| `LoggingEnabled`             | `Bool`   | true if logging is on, false if logging is off.           |
| `S3KeyPrefix`                | `String` | The prefix applied to the log file names.                 |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "AllowVersionUpgrade": true,
    "Arn": "arn:aws:redshift:us-west-2:123456789012:cluster:example-cluster",
    "AutomatedSnapshotRetentionPeriod": 1,
    "AvailabilityZone": "us-west-2c",
    "ClusterAvailabilityStatus": "Available",
    "ClusterNodes": [
        {
            "NodeRole": "LEADER",
            "PrivateIPAddress": "10.10.10.10",
            "PublicIPAddress": "111.111.111.111"
        },
        {
            "NodeRole": "COMPUTE-0",
            "PrivateIPAddress": "10.10.10.11",
            "PublicIPAddress": "111.111.111.112"
        }
    ],
    "ClusterParameterGroups": [
        {
            "ClusterParameterStatusList": null,
            "ParameterApplyStatus": "in-sync",
            "ParameterGroupName": "default.redshift-1.0"
        }
    ],
    "ClusterPublicKey": "ssh-rsa AAAA= Amazon-Redshift\n",
    "ClusterRevisionNumber": "10000",
    "ClusterSecurityGroups": null,
    "ClusterSnapshotCopyStatus": null,
    "ClusterStatus": "available",
    "ClusterSubnetGroupName": "default",
    "ClusterVersion": "1.0",
    "DataTransferProgress": null,
    "DeferredMaintenanceWindows": null,
    "ElasticIpStatus": null,
    "ElasticResizeNumberOfNodeOptions": "[3]",
    "Encrypted": false,
    "Endpoint": {
        "Address": "example-cluster.1111.us-west-2.redshift.amazonaws.com",
        "Port": 1234
    },
    "EnhancedVpcRouting": false,
    "HsmStatus": null,
    "IamRoles": null,
    "Id": "example-cluster",
    "KmsKeyId": null,
    "LoggingStatus": {
        "BucketName": null,
        "LastFailureMessage": null,
        "LastFailureTime": null,
        "LastSuccessfulDeliveryTime": null,
        "LoggingEnabled": false,
        "S3KeyPrefix": null
    },
    "MaintenanceTrackName": "current",
    "ManualSnapshotRetentionPeriod": -1,
    "MasterUsername": "awsuser",
    "ModifyStatus": null,
    "Name": "dev",
    "NodeType": "dc2.large",
    "NumberOfNodes": 2,
    "PendingActions": null,
    "PendingModifiedValues": {
        "AutomatedSnapshotRetentionPeriod": null,
        "ClusterIdentifier": null,
        "ClusterType": null,
        "ClusterVersion": null,
        "EncryptionType": null,
        "EnhancedVpcRouting": null,
        "MaintenanceTrackName": null,
        "MasterUserPassword": null,
        "NodeType": null,
        "NumberOfNodes": null,
        "PubliclyAccessible": null
    },
    "PreferredMaintenanceWindow": "sat:10:30-sat:11:00",
    "PubliclyAccessible": true,
    "Region": "us-west-2",
    "ResizeInfo": null,
    "ResourceId": "arn:aws:redshift:us-west-2:123456789012:cluster:example-cluster",
    "ResourceType": "AWS.Redshift.Cluster",
    "RestoreStatus": null,
    "SnapshotScheduleIdentifier": null,
    "SnapshotScheduleState": null,
    "Tags": {
        "Key1": "Value1"
    },
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "VpcId": "vpc-1",
    "VpcSecurityGroups": null
}
```
