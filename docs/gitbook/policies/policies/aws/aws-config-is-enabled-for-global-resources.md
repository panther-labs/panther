# AWS Config Is Enabled for Global Resources

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that at least one AWS Config recorder is configured to record changes to global resources, such as IAM entities.

**Remediation**

To remediate this, enable global resources for at least one active AWS Config recorder in the account.

**Reference**

- AWS Config [Selecting Resources to Record](https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html) documentation
