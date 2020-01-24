# AWS EC2 Gateway Modified

This rule monitors for changes to EC2 Gateways.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

EC2 Gateways broker access between your AWS resources and the internet, and so changes to the must be closely monitored and reviewed. Ensure that only planned changes are taking place.

**Remediation**

If this change was not planned before hand, revert it and investigate the source of the change. If it was due to improper policies/procedures, consider modifying permissions to prevent this from happening again.

**References**

- CIS AWS Benchmark 3.12: "Ensure a log metric filter and alarm exist for changes to network gateways"
