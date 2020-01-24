# AWS IAM Policy Modified

This rule monitors for changes to IAM policies.

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low**            |

IAM policies control what AWS entities have access to other AWS entities. These changes should be very closely monitored, as poor IAM configuration \(accidental or malicious\) is a major cause of AWS breaches.

**Remediation**

Verify that the IAM changes observed were planned and are reasonably executed. For example, make sure new IAM policies grant access to specific resources and not all resources. If these IAM policy changes were not planned, immediately revoke them and investigate the source of the changes.

**References**

- CIS AWS Benchmark 3.4: "Ensure a log metric filter and alarm exist for IAM policy changes"
