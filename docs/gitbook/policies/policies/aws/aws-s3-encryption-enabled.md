# AWS S3 Bucket Has Encryption Enabled

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that all S3 Buckets have server side encryption enabled. Server side encryption provides an additional layer of security, as access to both the bucket contents and bucket encryption keys must be compromised in order to compromise the contents of the bucket.

**Remediation**

To remediate this, enable server side bucket encryption for all S3 buckets.

**Reference**

- AWS S3 Bucket [default encryption](https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html) documentation
