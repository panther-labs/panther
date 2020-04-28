# AWS CloudTrail Modified

This rule monitors for modifications to AWS CloudTrails.

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low / High**     |

CloudTrail is the AWS auditing service, and modifications may mean loss of sensitive audit data. AWS CloudTrails should be modified very rarely, and modifications closely monitored and approved.

**Remediation**

If this CloudTrail change was not planned, review the CloudTrail event history to see what changes were made and by who. Revert inappropriate changes, and revoke access as necessary. Remember that disabling/modifying CloudTrail can prevent future audit logs from being generated, investigate your AWS environment for other changes if logging was temporarily disabled.

**References**

- CIS AWS Benchmark 3.5: "Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
