# AWS Password Policy Prevents Password Reuse

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low**            |

This policy validates that the account password policy prevents users from re-using previous passwords, and prevents password reuse for 24 or more prior passwords.

Preventing password reuse means that when passwords are rotated they are changed to new passwords. This is considered best security practice as if users are constantly switching between a small number of passwords, when one is compromised the password reset will not prevent its use for long effectively negating the effect of enforcing regular password resets.

**Remediation**

To remediate this, set the account password policy to prevent password reuse and set number of passwords to remember to be 24 or more.

| Using the AWS Console                                                                                                |
| :------------------------------------------------------------------------------------------------------------------- |
| 1. Access the [Account Settings](https://console.aws.amazon.com/iam/home?#/account_settings) tab in the AWS Console. |
| 2. Check the "Prevent password reuse " checkbox.                                                                     |
| 3. In the "Number of passwords to remember" text box, enter a number 24 or greater.                                  |

| Using the AWS CLI Tool                                                                                                                                                                                                         |
| :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. To update the account password policy to meet all of Panther's recommendations for complexity, password age, and password reuse, use the following command:                                                                 |
| `aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24`   |
| 2. Alternatively, to just enforce password reuse prevention, use the following command. Note: since this command does not allow for partial updates, this command will remove any password complexity or age requirements set: |
| `aws iam update-account-password-policy --password-reuse-prevention 24`                                                                                                                                                        |

**References**

- CIS AWS Benchmark 1.10 "Ensure IAM password policy prevents password reuse".
- [AWS CLI update-account-password-policy command](https://docs.aws.amazon.com/cli/latest/reference/iam/update-account-password-policy.html).
