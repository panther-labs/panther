# AWS S3 Bucket Has Versioning Enabled

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that all S3 Buckets have object versioning enabled. Object versioning protects have overwriting and deleting objects in a bucket by keeping multiple versions of the bucket.

**Remediation**

To remediate this, enable object versioning in all S3 buckets

**Reference**

- AWS S3 Bucket [object versioning](https://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectVersioning.html) documentation
