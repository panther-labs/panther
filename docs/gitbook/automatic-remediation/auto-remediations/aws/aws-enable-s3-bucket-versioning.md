# AWS Enable S3 Bucket Versioning

#### Remediation Id

`AWS.S3.EnableBucketVersioning`

#### Description

Remediation that enables 3 bucket versioning.

#### Resource Parameters

| Name        | Description                      |
| :---------- | :------------------------------- |
| `AccountId` | The AWS Account Id of the bucket |
| `Region`    | The AWS region of the bucket     |
| `Name`      | The name of the S3 bucket        |

#### References

- [https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-versioning.html](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-versioning.html)
- [https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html](https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html)
