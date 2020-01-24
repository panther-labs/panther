# AWS Password Policy Enforces Password Age Limit Of 90 Days Or Less

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low**            |

This policy validates that the account password policy enforces a maximum password age of 90 days or less.

Enforcing a max password age means that passwords will be regularly rotated. This is considered best security practice as it reduces the time possible for attackers to compromise passwords, and to make use of compromised credentials.

**Remediation**

To remediate this, set the account password policy's max password age to 90 days or less.

| Using the AWS Console                                                                                                |
| :------------------------------------------------------------------------------------------------------------------- |
| 1. Access the [Account Settings](https://console.aws.amazon.com/iam/home?#/account_settings) tab in the AWS Console. |
| 2. Check the "Enable password expiration" checkbox.                                                                  |
| 3. In the "Password expiration period \(in days\)" text box, enter a number 90 or less.                              |

| Using the AWS CLI Tool                                                                                                                                                                                                       |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. To update the account password policy to meet all of Panther's recommendations for complexity, password age, and password reuse, use the following command:                                                               |
| `aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24` |
| 2. Alternatively, to just enforce the max password age, use the following command. Note: since this command does not allow for partial updates, this command will remove any password complexity and reuse requirements:     |
| `aws iam update-account-password-policy --max-password-age 90`                                                                                                                                                               |

**References**

- CIS AWS Benchmark 1.11 "Ensure IAM password policy expires passwords within 90 days or less".
- [AWS CLI update-account-password-policy command](https://docs.aws.amazon.com/cli/latest/reference/iam/update-account-password-policy.html).
