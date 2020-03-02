# AWS Root Access Key Created

This rule monitors for the creation of IAM access keys for the root account.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Critical** | **Low**            |

The AWS root account has complete access to everything in an AWS account, much like the root user on Unix system or a user administrator on a windows machine. Best practice dictates that this account should not be used for day to day or regular activities, as that increases the chance of it being compromised. Creating root access keys is especially dangerous, as if they are compromised the attacker has unlimited and non-expiring access to the AWS account until the key is disabled. Only very few actions REQUIRE the use of the root access key, and in almost all cases the key can be revoked shortly after. 

**Remediation**

If an unplanned root access key is created, it should immediately be disabled and all active root sessions should be stopped. Immediately investigate who created the root access key and how, and investigate what actions were taken with the key. CloudTrail can be a particularly effective tool for investigating these things.

**References**

- [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials)
- [AWS Tasks that require root](https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html)
- CIS AWS Benchmark 1.12: "Ensure no root account access key exists"
