# AWS Config Records All Resource Types

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that AWS Config recorders are configured to monitor all possible resource types in the account. This provides a thorough monitoring of configuration changes in the account.

**Remediation**

To remediate this, configure each AWS Config Recorder in the account to record changes for all supported resources.

**Reference**

- AWS Config [Selecting Resources to Record](https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html) documentation
