# AWS EC2 Route Table Modified

This rule monitors for changes to EC2 Route tables.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

Route tables control the flow of traffic within your AWS environment. Changes to route tables could mean sensitive traffic is routed to systems outside of your control.

**Remediation**

If this change was not planned, revert it and investigate the source of the change. Consider modifying permissions to ensure unplanned changes cannot happen again in the future.

**References**

- CIS AWS Benchmark 3.13: "Ensure a log metric filter and alarm exist for route table changes"
