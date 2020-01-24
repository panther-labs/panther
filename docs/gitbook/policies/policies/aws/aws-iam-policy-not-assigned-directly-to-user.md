# AWS IAM Policy Is Not Assigned Directly To User

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **High**           |

This policy validates that there are no IAM policies assigned directly to users instead of being assigned to an IAM group or role.

Assigning an IAM policy to users directly increases complexity of access management and vastly increases the difficulty in maintaining proper least access controls in moderate to large size AWS accounts.

**Remediation**

To remediate this, for each IAM policy assigned directly to a user create a corresponding AWS role/group or roles/groups as appropriate. Then apply those IAM policies to the role/group or roles/groups just created. Finally move the users into the new groups/roles as appropriate and remove the IAM policy from the user.

Groups are a management convenience used to group permissions for users that need similar permissions. Roles are for delegating permissions tasks to a specific entity \(role\), which users can then explicitly assume to perform tasks. In these instructions, we will show how to move an IAM policy from a user to a group, then move that user to that group. For more information on roles vs. groups, see the reference section below.

| Using the AWS Console                                                                                                                                                    |
| :----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Access the IAM groups tab at:                                                                                                                                         |
| [https://console.aws.amazon.com/iam/home\#/groups](https://console.aws.amazon.com/iam/home#/groups)                                                                      |
| 2. Select the "Create New Group" button.                                                                                                                                 |
| 3. Name the group and select the "Next Step" button.                                                                                                                     |
| 4. In the "Attach Policy" section, select the policy or policies attached directly to a user that you wish to move to this group and then select the "Next Step" button. |
| 5. Select the "Create Group" button.                                                                                                                                     |
| 6. Now access the IAM users tab at:                                                                                                                                      |
| [https://console.aws.amazon.com/iam/home\#/users/](https://console.aws.amazon.com/iam/home#/users/)                                                                      |
| 7. Select the user you wish to add to this group.                                                                                                                        |
| 8. Select the "Groups" tab, select the "Add user to groups" button, select the newly created group or groups, then select the "Add to groups" button.                    |
| 9. Select the "Permissions" tab, select the gray "x" button for the policy you've just added to a group, and select the "Detach" button in the popup window.             |

| Using the AWS CLI Tool                                                                                    |
| :-------------------------------------------------------------------------------------------------------- |
| 1. Run the following command to create a new IAM group:                                                   |
| `aws iam create-group --group-name <group_name>`                                                          |
| 2. Run the following command to attach the policy to be removed from the user to the group created above: |
| `aws iam attach-group-policy --group-name <group_name> --policy-arn <policy_arn>`                         |
| 3. Run the following command to add the user to the newly created group:                                  |
| `aws iam add-user-to-group --user-name <user_name> --group-name <group_name>`                             |
| 4. Run the following command to remove the policy from the user just added to the group:                  |
| `aws iam detach-user-policy --user-name <user_name> --policy-arn <policy_arn>`                            |

**References**

- CIS AWS Benchmark 1.16 "Ensure IAM policies are attached only to groups or roles".
- [IAM FAQ](https://aws.amazon.com/iam/faqs/#IAM_user_management).
