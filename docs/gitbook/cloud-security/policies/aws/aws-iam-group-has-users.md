# AWS IAM Group Has Users

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that every IAM Group has at least one IAM user in it. Unused groups increase management complexity and attack surface, and should be deleted.

**Remediation**

To remediate this, delete any IAM groups that do not have any users in them. Alternatively, add appropriate users to the groups.

**Reference**

- AWS [Deleting IAM Groups](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups_manage_delete.html) documentation
