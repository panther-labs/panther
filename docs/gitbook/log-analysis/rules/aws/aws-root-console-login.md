# AWS Root Console Login

This rule monitors for root account console logins.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **High** | **Low**            |

The AWS root account has complete access to everything in an AWS account, much like the root user on Unix system or a user administrator on a windows machine. Best practice dictates that this account should not be used for day to day or regular activities, as that increases the chance of it being compromised. Only very few actions REQUIRE the use of the root access key, and these instances of root account use should be very closely monitored. 

**Remediation**

If an unplanned root login is detected, all active root sessions should be stopped. Immediately change the root account credentials, and investigate what actions by any unauthorized logins to the root account. CloudTrail can be a particularly effective tool for investigating these things.

**References**

- [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#create-iam-users)
- [AWS Tasks that require root](https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html)
- CIS AWS Benchmark 1.1: "Avoid the use of the "root" account"
