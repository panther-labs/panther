# AWS CloudFormation Stack Has Not Drifted

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low**            |

This policy validates that no CloudFormation stacks have drifted from their original template.

Drifted stacks indicate that the AWS environment is no longer configured the way it was intended to be, which may be indicator of malicious behavior or other undocumented changes.

**Remediation**

To remediate this, you can re-apply the stack to restore it to its original state from the AWS [CloudFormation panel](https://us-west-2.console.aws.amazon.com/cloudformation/home).

Besides just fixing the stack, it is important to evaluate the impact and cause of the changes. A resource being renamed may be relatively benign, but an access policy changing or a resource being deleted could be a sign of malicious behavior. Reviewing logs in CloudTrail can help determine the what caused this change so it can be prevented in the future, and can help investigators evaluate whether the change was malicious or accidental and any potential further impacts of the change.

| Using the AWS Console                                                                                                           |
| :------------------------------------------------------------------------------------------------------------------------------ |
| 1. Navigate to the stacks tab of the AWS [CloudFormation ](https://us-west-2.console.aws.amazon.com/cloudformation/home)console |
| 2. Select the stack that is out of sync                                                                                         |
| 3. Select the `Update` button                                                                                                   |
| 4. Select the `Use current template` radio button                                                                               |
| 5. Confirm all parameters and advanced options are configured as intended, selecting the `Next` button as you do so             |
| 6. Select the `Update stack` button                                                                                             |

**Reference**

- AWS [CloudFormation Stack Updates](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks.html) documentation
