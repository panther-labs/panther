# AWS Access Keys not Created During Account Creation

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that AWS IAM user accounts do not have access keys that were created during account creation.

If IAM access keys are not being used, they should not exist. Creating access keys at the time of account creation generally leads to outdated access keys being created over time. As a best practice, it is recommended to create account access keys as part of an explicit and separate process from account creation.

**Remediation**

To remediate this, disable or delete all access keys that were created at account creation that are not in use, and rotate any access keys that were created at account creation and are still in use. Be sure to document this activity per your standard AWS access key request process.

| Using the AWS Console                                                                                                                                                                                                                          |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Navigate to the [AWS IAM Console](https://console.aws.amazon.com/iam/home#/users).                                                                                                                                                          |
| 2. Select the user with access keys that were created at account creation.                                                                                                                                                                     |
| 3. Select the "Security credentials" tab.                                                                                                                                                                                                      |
| 4. Under the "Access keys" header, select the "Make inactive" button or the "X" icon delete button of the first access key if it is not in use.                                                                                                |
| 5. If the access key is in use rotate the access key by first creating a new access key, switching over any scripts/programmatic access to use the new access key, verify that the new access key is working, then take the actions in step 4. |

| Using the AWS CLI                                                                                                                                                                                                                   |
| :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. To delete an unnecessary access key, run the following command:                                                                                                                                                                  |
| `aws iam delete-access-key --user-name <user_name> --access-key-id <access_key_id>`                                                                                                                                                 |
| 2. To alternatively rotate a key instead of deleting it, view the remediation steps for [AWS Access Keys are Rotated Every 90 Days](https://docs.runpanther.io/amazon-web-services/policies/aws-access-keys-rotated-every-90-days). |

**References**

- CIS AWS Benchmark 1.21 "Do not setup access keys during initial user setup for all IAM users that have a console password"
