# AWS Config Service Modified

This rule monitors for modifications to AWS Config.

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low**            |

AWS Config is a configuration monitoring tool, and changes to it could mean loss of visibility into configuration changes in your AWS account.

**Remediation**

If this Config change was not planned, revert the change and investigate who initiated it.

**References**

- CIS AWS Benchmark 3.9: "Ensure a log metric filter and alarm exist for AWS Config configuration changes"
