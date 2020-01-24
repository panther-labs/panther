# CloudTrail

#### Resource Type

`AWS.CloudTrail`

#### Resource ID Format

For CloudTrail Trails, the resource ID is the ARN.

`arn:aws:cloudtrail:us-west-2:123456789012:trail/example-trail`

#### Background

The [CloudTrail](https://aws.amazon.com/cloudtrail/) resource represents the system within AWS responsible for tracking account activity.

#### Fields

| Field            | Type   | Description                                                                                                                |
| :--------------- | :----- | :------------------------------------------------------------------------------------------------------------------------- |
| `EventSelectors` | `List` | The collection of management and data event settings across each CloudTrail in each region                                 |
| `Status`         | `Map`  | CloudTrail [status](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html) of last events. |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:cloudtrail:us-west-2:123456789012:trail/example-trail",
    "CloudWatchLogsLogGroupArn": null,
    "CloudWatchLogsRoleArn": null,
    "EventSelectors": [
        {
            "DataResources": [
                {
                    "Type": "AWS::S3::Object",
                    "Values": null
                }
            ],
            "IncludeManagementEvents": true,
            "ReadWriteType": "All"
        }
    ],
    "HasCustomEventSelectors": true,
    "HomeRegion": "us-west-2",
    "IncludeGlobalServiceEvents": true,
    "IsMultiRegionTrail": true,
    "IsOrganizationTrail": true,
    "KmsKeyId": "arn:aws:kms:us-west-2:123456789012:key/1111",
    "LogFileValidationEnabled": true,
    "Name": "example-trail",
    "Region": "us-west-2",
    "ResourceId": "arn:aws:cloudtrail:us-west-2:123456789012:trail/example-trail",
    "ResourceType": "AWS.CloudTrail",
    "S3BucketName": "example-bucket",
    "S3KeyPrefix": null,
    "SnsTopicARN": "arn:aws:sns:us-west-2:123456789012:example-topic",
    "SnsTopicName": "arn:aws:sns:us-west-2:123456789012:example-topic",
    "Status": {
        "IsLogging": true,
        "LatestCloudWatchLogsDeliveryError": null,
        "LatestCloudWatchLogsDeliveryTime": null,
        "LatestDeliveryAttemptSucceeded": "2019-01-01T00:00:00Z",
        "LatestDeliveryAttemptTime": "2019-01-01T00:00:00Z",
        "LatestDeliveryError": null,
        "LatestDeliveryTime": "2019-01-01T00:00:00Z",
        "LatestDigestDeliveryError": null,
        "LatestDigestDeliveryTime": "2019-01-01T00:00:00Z",
        "LatestNotificationAttemptSucceeded": "2019-01-01T00:00:00Z",
        "LatestNotificationAttemptTime": "2019-01-01T00:00:00Z",
        "LatestNotificationError": null,
        "LatestNotificationTime": "2019-01-01T00:00:00Z",
        "StartLoggingTime": "2019-01-01T00:00:00Z",
        "StopLoggingTime": null,
        "TimeLoggingStarted": "2019-01-01T00:00:00Z",
        "TimeLoggingStopped": null
    },
    "Tags": null,
    "TimeCreated": null
}
```
