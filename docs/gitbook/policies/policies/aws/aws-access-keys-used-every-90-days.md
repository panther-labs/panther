# AWS Access Keys Are Used Every 90 Days

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that IAM user access keys are used at least once every 90 days.

Access keys provide programatic access to an AWS account, and if those keys are not in use they should not be enabled as they only serve to increase the attack surface of the account.

**Remediation**

To remediate this, each unused credential for each user mentioned in this alert should be made inactive.

| Using the AWS Console                                                                                   |
| :------------------------------------------------------------------------------------------------------ |
| 1. Access the User tab of the IAM console at:                                                           |
| [https://console.aws.amazon.com/iam/home\#/users](https://console.aws.amazon.com/iam/home#/users)       |
| 2. Select the name of the non-compliant user.                                                           |
| 3. Select the "Security Credentials" tab.                                                               |
| 4. Under the "Access Keys" section select "Make inactive" under the "Status" column for the unused key. |

| Using the AWS CLI Tool                                                                                |
| :---------------------------------------------------------------------------------------------------- |
| 1. Run the following command to make the unused access key inactive:                                  |
| `aws iam update-access-key --user-name <user_name> --access-key-id <access_key_id> --status Inactive` |

**References**

- CIS AWS Benchmark 1.3 "Ensure credentials unused for 90 days or greater are disabled."
