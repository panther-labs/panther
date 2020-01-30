# AWS CloudWatch Logs Are Encrypted

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that all CloudWatch Logs are encrypted. CloudWatch logs can contain extremely sensitive information, and encrypting them ensures they are protected more carefully.

**Remediation**

To remediate this, create a KMS CMK with the appropriate permissions for the CloudWatch service to use it and associate it to the log group.

**Reference**

- AWS CloudWatch [Encrypt Log Data Using KMS](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html) documentation
