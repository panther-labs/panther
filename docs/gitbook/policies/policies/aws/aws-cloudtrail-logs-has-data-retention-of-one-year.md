# AWS CloudWatch Logs Has Data Retention of One Year

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that all CloudWatch Log Groups have a data retention period of at least one year.

Audit logs are often required to be kept for a minimum period of time by various compliance frameworks to ensure their accessibility in the case of an incident. The retention period can be modified as need from within this policy.

**Remediation**

To remediate this, increase the data retention period of each CloudWatch Log group to at least one year.

**Reference**

- AWS CloudWatch [PutRetentionPolicy](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutRetentionPolicy.html) documentation
