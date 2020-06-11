# CloudWatch Log Group

#### Resource Type

`AWS.CloudWatch.LogGroup`

#### Resource ID Format

For CloudWatch Log Groups, the resource ID is the ARN.

`arn:aws:logs:us-west-2:123456789012:log-group:/prefix/groupname:*`

#### Background

CloudWatch Logs enables teams to centralize logs from systems, applications, and AWS services.

#### Fields

| Field               | Type     | Description                                                                                                             |
| :------------------ | :------- | :---------------------------------------------------------------------------------------------------------------------- |
| `KmsKeyId`          | `String` | The Amazon Resource Name \(ARN\) of the CMK to use when encrypting log data.                                            |
| `MetricFilterCount` | `Int`    | The number of metric filters.                                                                                           |
| `RetentionInDays`   | `Int`    | The number of days to retain the log events in the specified log group. If this value is `null`, logs are kept forever. |
| `StoredBytes`       | `Int`    | The number of bytes stored in the log group.                                                                            |

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:logs:us-west-2:123456789012:log-group:/prefix/groupname:*",
    "KmsKeyId": null,
    "MetricFilterCount": 0,
    "Name": "/prefix/groupname",
    "Region": "us-west-2",
    "ResourceId": "arn:aws:logs:us-west-2:123456789012:log-group:/prefix/groupname:*",
    "ResourceType": "AWS.CloudWatch.LogGroup",
    "RetentionInDays": 365,
    "StoredBytes": 100000,
    "Tags": null,
    "TimeCreated": "2019-01-01T00:00:00.000Z"
}
```
