# AWS IAM Entity Created Without CloudFormation

This rule monitors for the manual creation of IAM entities.

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Medium**            |

IAM entities control permissions in your AWS account. These entities and their management should be tightly controlled. Attackers may create new IAM entities manually in order to establish persistence in a compromised AWS account.

**Remediation**

Any IAM entities created manually should be reviewed. If the entity should exist, then it should be added to the CloudFormation stack responsible for administrating IAM in your organization. If the entity should not exist, it should be deleted immediately and you should review the CloudTrail logs to see who created this entity and whether an account may have been compromised.

**References**

- https://blog.runpanther.io/secure-multi-account-aws-access/
