# AWS KMS CMK Loss

This rule monitors for activity that could lead to the loss of KMS Customer Managed Keys \(CMKs\).

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

KMS CMKs cannot be directly deleted by users, but are instead scheduled for deletion at some point at least 7 days in the future. Once these keys are deleted, there is no way to decrypt data encrypted with them.

**Remediation**

Ensure that the key deletion was planned, and that it will not cause loss of access to sensitive or critical data.

**References**

- CIS AWS Benchmark 3.7: "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs"
