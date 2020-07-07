# AWS IAM Policy Role Mapping Is Respected

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that certain policies are attached to certain roles. This can be used to ensure that certain restrictive policies are applied to certain roles to manage their access.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, attach the policy to each role it is required to be attached to.

**Reference**

- AWS [attach-role-policy](https://docs.aws.amazon.com/cli/latest/reference/iam/attach-role-policy.html) documentation
