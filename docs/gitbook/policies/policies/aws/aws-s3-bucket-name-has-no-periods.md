# AWS S3 Bucket Name Has No Periods

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **Info** | **Medium**         |

This policy validates that no S3 buckets have periods `.` in their name. This is a recommended best practice from AWS, that ensures that the buckets will be able to take advantage of some more advanced features of S3 that require DNS compliant names.

**Remediation**

To remediate this, create new S3 buckets with compliant names and move the contents of the non-compliant bucket into the compliant bucket. Then delete the non-compliant bucket.

**Reference**

- AWS S3 [transfer acceleration](https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html) documentation
