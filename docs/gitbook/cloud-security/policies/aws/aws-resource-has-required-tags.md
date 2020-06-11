# AWS Resource Has Required Tags

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Medium**         |

This policy validates that each resource has certain tag keys, dependent on the resource type. This allows you to ensure that all EC2 Instances have one set of tag Keys, while all RDS Instances have another.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, tag each resource with key/value pairs as appropriate for that resource type.

**Reference**

- AWS [tagging strategies](https://aws.amazon.com/answers/account-management/aws-tagging-strategies/) documentation
