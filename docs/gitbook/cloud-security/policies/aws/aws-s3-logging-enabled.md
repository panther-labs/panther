# AWS S3 Bucket Has Logging Enabled

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that all S3 Buckets have access logging enabled. Access logging creates a record of who is accessing what within a given bucket, an important audit trail during investigations.

**Remediation**

To remediate this, enable S3 bucket access logging for each S3 bucket.

**Reference**

- AWS S3 Bucket [access logging](https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html) documentation
