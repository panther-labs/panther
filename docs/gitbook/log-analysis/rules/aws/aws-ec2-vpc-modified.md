# AWS EC2 VPC Modified

This rule monitors for failed AWS changes to EC2 VPCs.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

EC2 VPCs have broad control/impact on how network traffic traverses your AWS environment. Changes to these systems should be closely monitored as they could open access to sensitive internal systems to attackers.

**Remediation**

If this change was not planned, revert it and investigate the source of the change. Consider modifying permissions to ensure unplanned changes cannot happen again in the future.

**References**

- CIS AWS Benchmark 3.14: "Ensure a log metric filter and alarm exist for VPC changes"
