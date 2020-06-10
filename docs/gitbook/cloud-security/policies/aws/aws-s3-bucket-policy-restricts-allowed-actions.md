# AWS S3 Bucket Policy Restricts Allowed Actions

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low**            |

This policy validates that S3 Bucket access policies do not allow any action on the bucket, in accordance with the principle of least privilege.

**Remediation**

To remediate this, modify any grants in the S3 Bucket access policy that have `Effect:Allow` on `Actions:*` or `Actions:s3:*`. New, more restrictive grants may be needed in their place to maintain access.

**Reference**

- AWS S3 Bucket [example policies](https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html)
