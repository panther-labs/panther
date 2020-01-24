# AWS CloudFormation Stack Has Termination Protection

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **Info** | **Low**            |

This policy validates that all CloudFormation stacks have termination protection enabled. This prevents stacks from being accidentally deleted, either manually or by services such as CloudFormation and Terraform.

This setting is only needed for important stacks that should not be deleted in the normal course of CloudFormation administration, such as stacks managing IAM entities for the account.

**Remediation**

To remediate this, manually enable termination protection from the AWS [CloudFormation ](https://us-west-2.console.aws.amazon.com/cloudformation/home) console.

| Using the AWS Console                                                                                                           |
| :------------------------------------------------------------------------------------------------------------------------------ |
| 1. Navigate to the stacks tab of the AWS [CloudFormation ](https://us-west-2.console.aws.amazon.com/cloudformation/home)console |
| 2. Select the stack that needs termination protection                                                                           |
| 3. Select the `Stack actions` button                                                                                            |
| 4. Select `Edit termination protection`                                                                                         |
| 5. Select the `Enabled` radio button, then the `Save` button                                                                    |

**Reference**

- AWS CloudFormation [Protecting a Stack](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-protect-stacks.html) documentation
