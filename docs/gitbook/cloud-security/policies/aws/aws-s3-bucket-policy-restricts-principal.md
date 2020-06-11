# AWS S3 Bucket Policy Restricts Principal

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that S3 Bucket access policies do not allow any principal for a given action on the bucket, in accordance with the principle of least privilege.

**Remediation**

To remediate this, modify any grants in the S3 Bucket access policy that have `Effect:Allow` on `Princiapl:*`. New, more restrictive grants may be needed in their place to maintain access.

**Reference**

- AWS S3 Bucket [example policies](https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html)
