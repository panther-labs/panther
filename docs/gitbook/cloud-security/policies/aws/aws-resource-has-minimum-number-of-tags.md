# AWS Resource Has Minimum Number of Tags

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Medium**         |

This policy validates that all AWS resources in the account that can have tags applied have the minimum number of tags necessary. This minimum number of tags is unique to any individual organization, where tags may be used to determine environment \(i.e. `prod` vs `dev`\), team \(i.e. `IT` vs `HR`\), source CloudFormation/Terraform stack, or other organization specific information.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, tag all resources as required by your organization's conventions.

**Reference**

- AWS [tagging strategies](https://aws.amazon.com/answers/account-management/aws-tagging-strategies/) documentation
