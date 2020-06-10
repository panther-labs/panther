# AWS S3 Bucket Has Public Access Block Enabled

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that all S3 Buckets have a public access block configuration enabled. This is a configuration that can override bucket access policies and prevent public read or write access to the bucket, or even prevent such policies from being applied in the first place.

**Remediation**

To remediate this, configure a block public access configuration on each S3 bucket.

**Reference**

- AWS S3 [Using Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html) documentation
