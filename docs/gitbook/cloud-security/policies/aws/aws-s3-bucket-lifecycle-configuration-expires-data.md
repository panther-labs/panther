# AWS S3 Bucket Lifecycle Configuration Expires Data

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that S3 Bucket lifecycle configurations expire data within a reasonable time frame. This sets both an upper and lower bound on data expiration times.

**Remediation**

To remediate this, configure the lifecycle configuration of each bucket in accordance with the organizations policies

**Reference**

- AWS S3 Bucket [lifecycle policy](https://docs.aws.amazon.com/AmazonS3/latest/user-guide/create-lifecycle.html) documentation
