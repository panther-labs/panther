# AWS Create CloudTrail

#### Remediation Id

`AWS.CloudTrail.CreateTrail`

#### Description

Remediation that creates a new CloudTrail trail that sends to S3.

#### Resource Parameters

| Name        | Description                            |
| :---------- | :------------------------------------- |
| `AccountId` | The AWS Account Id to create the trail |
| `Region`    | The AWS region to create the trail in  |

#### Additional Parameters

| Name                         | Description                                                                                                                                                                                                                                                                             |
| :--------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Name`                       | The name of the trail                                                                                                                                                                                                                                                                   |
| `TargetBucketName`           | Specifies the name of the Amazon S3 bucket designated for publishing log files                                                                                                                                                                                                          |
| `TargetPrefix`               | Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery                                                                                                                                                                    |
| `SnsTopicName`               | Specifies the name of the Amazon SNS topic defined for notification of log file delivery. If empty, no SNS notifications will be sent.                                                                                                                                                  |
| `IsMultiRegionTrail`         | Specifies whether the trail is created in the current region or in all regions.                                                                                                                                                                                                         |
| `KmsKeyId`                   | Specifies the KMS key ID to use to encrypt the logs delivered by CloudTrail. If empty, the logs will not be encrypted.                                                                                                                                                                  |
| `IncludeGlobalServiceEvents` | Specifies whether the trail is publishing events from global services such as IAM to the log files.                                                                                                                                                                                     |
| `IsOrganizationTrail`        | Specifies whether the trail is created for all accounts in an organization in AWS Organizations, or only for the current AWS account. It cannot be set to true unless the call is made on behalf of an AWS account that is the master account for an organization in AWS Organizations. |

#### References

- [https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/create-trail.html](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/create-trail.html)
