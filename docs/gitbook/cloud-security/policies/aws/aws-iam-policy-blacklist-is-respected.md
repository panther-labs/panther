# AWS IAM Policy Blacklist Is Respected

| Risk         | Remediation Effort |
| :----------- | :----------------- |
| **Critical** | **Low**            |

This policy validates that no blacklisted IAM policies are assigned to any IAM entities. This can be used to blacklist certain AWS managed IAM policies \(such as various administrator level policies\) to ensure they are not in use in your account.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, un-attach the blacklisted policy from any IAM entities it is attached to.

**Reference**

- AWS [Adding and Removing IAM Permissions](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage-attach-detach.html) documentation
