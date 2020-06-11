# AWS S3 Bucket Not Publicly Readable

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that no S3 buckets are publicly readable. Overly permissive S3 buckets are a major cause of data loss in AWS. Be extremely careful when making buckets publicly available.

**Remediation**

To remediate this, modify the access policy of the S3 bucket to remove `AllUsers` and `AuthenticatedUsers` from any grant that gives read permissions.

**Reference**

- AWS S3 Bucket [example policies](https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html)
