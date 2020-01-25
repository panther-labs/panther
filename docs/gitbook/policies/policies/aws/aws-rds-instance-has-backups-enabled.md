# AWS RDS Instance Has Backups Enabled

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low**            |

This policy validates that all RDS Instances have backups enabled. A lack of backups can lead to data loss in the case of accidental or malicious data deletion.

**Remediation**

To remediate this, configure a backup retention period greater than 0.

**Reference**

- AWS RDS [Working With Backups](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html) documentation
