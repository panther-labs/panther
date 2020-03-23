# AWS EC2 SecurityGroup Modified

This rule monitors for changes to EC2 SecurityGroups.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

SecurityGroups limit the flow of traffic within your AWS environment. Changes to SecurityGroup configurations should be closely monitored to ensure that inappropriate or insecure access is not being introduced.

**Remediation**

If this change was not planned, revert it and investigate the source of the change. Consider modifying permissions to ensure unplanned changes cannot happen again in the future.

**References**

- CIS AWS Benchmark 3.10: "Ensure a log metric filter and alarm exist for security group changes"
