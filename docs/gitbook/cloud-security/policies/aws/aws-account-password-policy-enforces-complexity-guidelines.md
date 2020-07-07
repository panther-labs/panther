# AWS Password Policy Enforces Complexity Guidelines

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low**            |

This policy validates that the account password policy enforces the recommended password complexity requirements. The alert contains additional details on what was lacking in the password policy, including the following possibilities:

| Missing Requirements                                              |
| :---------------------------------------------------------------- |
| Policy does not require an uppercase letter                       |
| Policy does not require a lower case letter                       |
| Policy does not require a symbol                                  |
| Policy does not require a number                                  |
| Policy does not require a minimum length of 14 or more characters |

Weak passwords are faster to crack or brute force, increasing the likelihood that they will be compromised. By enforcing password complexity requirements, these issues can be mitigated.

**Remediation**

To remediate this, update the account password policy to include these complexity requirements. Note that this will not effect existing users or their passwords, so it is recommended to either do this in conjunction with automated/manual password resets, or to enforce regular \(90 day\) password updates in which case at the time of the next regular password update for each user the complexity requirements will be met.

| Using the AWS Console                                                                                                |
| :------------------------------------------------------------------------------------------------------------------- |
| 1. Access the [Account Settings](https://console.aws.amazon.com/iam/home?#/account_settings) tab in the AWS Console. |
| 2. In the "Minimum password length" box, put in a number greater or equal to 14.                                     |
| 3. From the checklist, check the appropriate boxes to enable the various complexity requirements.                    |

| Using the AWS CLI Tool                                                                                                                                                                                                       |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. To update the account password policy to meet all of Panther's recommendations for complexity, password age, and password reuse, use the following command:                                                               |
| `aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24` |
| 2. Alternatively, to just enforce the complexity requirements above, use the following command. Note: since this command does not allow for partial updates, this command will remove any age and reuse requirements:        |
| `aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters`                                                      |

**References**

- CIS AWS Benchmark 1.5, 1.6, 1.7, 1.8, 1.9.
- [AWS CLI update-account-password-policy command](https://docs.aws.amazon.com/cli/latest/reference/iam/update-account-password-policy.html).
