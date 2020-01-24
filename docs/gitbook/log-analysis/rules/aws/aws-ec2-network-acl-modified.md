# AWS EC2 Network ACL Modified

This rule monitors changes to EC2 Network ACls.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

Network ACLs limit the flow of network traffic within your AWS environment, as well as the flow of traffic to and from the internet. Changes to these configurations should be closely monitored to ensure that inappropriate or insecure access is not being introduced.

**Remediation**

If this change was not planned, revert it and investigate the source of the change. Consider modifying permissions to ensure unplanned changes cannot happen again in the future.

**References**

- CIS AWS Benchmark 3.11: "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists \(NACL\)"
