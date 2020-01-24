# AWS GuardDuty is Logging to a Master Account

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that all GuardDuty Detectors are sending logs to a specified master GuardDuty account. This is a best practice for centralizing log data.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, configure all GuardDuty detectors to send to the GuardDuty master.

**Reference**

- AWS [Managing GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html) documentation
