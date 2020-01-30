# AWS Root Activity

This rule monitors for any activity performed by the AWS root account.

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low / High**     |

Best practice dictates to not use the root account unless absolutely necessary, as it has complete access to everything within the account. Instead service roles and IAM users should be created which grant the least amount of privilege needed to perform a certain task. This rule supplements this practice by ensuring the root account is not used for anything.

**Remediation**

Verify that use of the root account was authorized, as there are a small number of tasks which require it. If use was not authorized, revoke access to the root account immediately and change the password. If MFA was enabled, rotate the MFA device as it may be compromised. Perform an extensive review of activities performed by the root account.

**References**

- CIS AWS Benchmark 3.3: "Ensure a log metric filter and alarm exist for usage of "root" account"
