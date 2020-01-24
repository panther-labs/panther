# AWS IAM Policy Does Not Grant Full Administrative Privileges

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **High**           |

This policy validates that there are no IAM policies that grant full administrative privileges to IAM users or groups.

The principle of least privilege dictates that any user should only have the relevant amount of access necessary to complete their task. Following the principle of least privilege is considered best security practice as it minimizes the damage that one user can do, either intentionally, unintentionally, or because their account was compromised. By splitting the access out into various groups/roles, and only assigning users to the groups/roles they have a reason to be a part of, this principle can be maintained. Having a user, role, or group with full administrative access defeats this principle.

**Remediation**

To remediate this, remove the policy/policies granting full access from any users, groups, or roles it is attached to. It may be necessary to create new policies encapsulating a smaller subset of access and apply those to roles/groups as necessary.

| Using the AWS Console                                                              |
| :--------------------------------------------------------------------------------- |
| 1. Access the [IAM Console](https://console.aws.amazon.com/iam/home#/policies).    |
| 2. Select the policy identified in the alert.                                      |
| 3. Select the "Policy usage" tab.                                                  |
| 4. Select each check box individually, or the select all checkbox at the top.      |
| 5. Select the "Detach" button, then the "Detach" button again in the popup window. |

| Using the AWS CLI Tool                                                                                     |
| :--------------------------------------------------------------------------------------------------------- |
| 1. Run the following command to get a list of all users, groups, and roles that have this policy attached: |
| `aws iam list-entities-for-policy --policy-arn <policy_arn>`                                               |
| 2. For each group returned by the command in step 1, run the following:                                    |
| `aws iam detach-group-policy --policy-arn <policy_arn> --group-name <group_name>`                          |
| 3. For each role entity returned by the command in step 1, run the the following:                          |
| `aws iam detach-role-policy --policy-arn <policy_arn> --role-name <role_name>`                             |
| 4. For each user entity returned by the command in step 1, run the following:                              |
| `aws iam detach-user-policy --policy-arn <policy_arn> --user-name <user_name>`                             |

**References**

- CIS AWS Benchmark 1.22 "Ensure IAM policies that allow full "_:_" administrative privileges are not created"
