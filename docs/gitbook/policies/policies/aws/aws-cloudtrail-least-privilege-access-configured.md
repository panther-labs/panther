# AWS CloudTrail Least Privilege Access Configured

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Medium**         |

This policy validates that the IAM group responsible for granting full CloudTrail access is restricted to a limited number of administrators. This helps enforce the principle of least privilege in accessing and managing the highly sensitive CloudTrail logs.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, reduce the number of users in the IAM group responsible for managing CloudTrail to the minimum necessary to perform the role.
