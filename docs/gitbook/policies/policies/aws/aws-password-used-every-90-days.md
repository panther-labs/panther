# AWS IAM Password Used Every 90 Days

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates IAM users with console passwords have logged in within the past 90 days.

Console passwords allow AWS console logins to anyone that possess the password \(and MFA token if MFA is enabled\). If the user is not using console access, this should be disabled to minimize the attack surface of the account.

**Remediation**

To remediate this, disable the password for each user mentioned in this alert.

| Using the AWS Console                                                                                                                                                                                                                                 |
| :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Access the User tab of the IAM console at:                                                                                                                                                                                                         |
| [https://console.aws.amazon.com/iam/home\#/users](https://console.aws.amazon.com/iam/home#/users)                                                                                                                                                     |
| 2. Select the name of the non-compliant user.                                                                                                                                                                                                         |
| 3. Select the "Security Credentials" tab.                                                                                                                                                                                                             |
| 4. Under the "Sign-in Credentials" section select "Manage" next to "Console password Enabled", then select "Disable" and "Apply" \(note that this will prevent the user from logging in from the console at a future date until this is re-enabled\). |

| Using the AWS CLI Tool                                       |
| :----------------------------------------------------------- |
| 1. Run the following commanD to delete the console password: |
| `aws iam delete-login-profile --user-name <user_name>`       |

**References**

- CIS AWS Benchmark 1.3 "Ensure credentials unused for 90 days or greater are disabled."
