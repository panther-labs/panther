# AWS EC2 Instance Has Detailed Monitoring Enabled

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that each EC2 Instance is running with detailed monitoring enabled. Detailed monitoring makes instance data available in 1 minute periods, as opposed to 5 minute periods for the Basic monitoring provided by default.

**Remediation**

To remediate this, enable detailed monitoring for each EC2 Instance.

**Reference**

- AWS EC2 [Enabling Detailed Monitoring](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html) documentation
