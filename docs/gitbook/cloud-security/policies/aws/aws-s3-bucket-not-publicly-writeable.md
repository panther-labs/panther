# AWS S3 Bucket Not Publicly Writeable

| Risk         | Remediation Effort |
| :----------- | :----------------- |
| **Critical** | **Low**            |

This policy validates that no S3 Buckets are publicly writeable. It is almost never the case that S3 buckets should be publicly writeable. Data in publicly writeable buckets is not safe, it may be deleted at any time by any person.

**Remediation**

To remediate this, modify the access policy of the S3 bucket to remove `AllUsers` and `AuthenticatedUsers` from any grant that gives write permissions.

**Reference**

- AWS S3 Bucket [example policies](https://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html)
