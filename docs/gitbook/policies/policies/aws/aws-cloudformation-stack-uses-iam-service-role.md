# AWS CloudFormation Stack Uses IAM Service Role

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **Info** | **Medium**         |

This policy validates that each CloudFormation stack uses an explicit IAM service role to perform its tasks.

This ensures that permissions granted to the CloudFormation stack cannot be accidentally granted to a user.

**Remediation**

To remediate this, create an IAM service role that can be assumed by the CloudFormation service and associate it to the stack.

**Reference**

- AWS CloudFormation [Using IAM Service Roles](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html) documentation
