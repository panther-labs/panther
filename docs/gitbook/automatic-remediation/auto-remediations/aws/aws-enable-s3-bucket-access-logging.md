# AWS Enable S3 Bucket Access Logging

#### Remediation Id

`AWS.S3.EnableBucketLogging`

#### Description

Remediation that enables S3 bucket access logging.

#### Resource Parameters

| Name        | Description                      |
| :---------- | :------------------------------- |
| `AccountId` | The AWS Account Id of the bucket |
| `Region`    | The AWS region of the bucket     |
| `Name`      | The name of the S3 bucket        |

#### Additional Parameters

| Name           | Description                                                                                                          |
| :------------- | :------------------------------------------------------------------------------------------------------------------- |
| `TargetBucket` | Specifies the name of the Amazon S3 bucket designated for publishing log files                                       |
| `TargetPrefix` | Specifies the Amazon S3 key prefix that comes after the name of the bucket you have designated for log file delivery |

#### References

- [https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html](https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html)
- [https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-logging.html](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-logging.html)
