# AWS Root Password Changed

This rule monitors for root account console logins.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Critical** | **Low**            |

The AWS root account has complete access to everything in an AWS account, much like the root user on Unix system or a user administrator on a windows machine. If the root account password is changed, access to the account may be entirely lost if not responded to in a timely manner.

**Remediation**

Verify that the root password change was authorized. If not, immediately attempt to reset the password as access to the account may be lost entirely if an attacker has compromised the root account and uses the access to change the contact information on the account. If access is re-gained, be sure to reset the MFA and password of the root account and conduct a thorough investigation of how the unauthorized root password change happened and what actions may have been carried out by the root user in that timeframe.


**References**

- [AWS docs - Resetting the root password](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys_retrieve.html#reset-root-password)
