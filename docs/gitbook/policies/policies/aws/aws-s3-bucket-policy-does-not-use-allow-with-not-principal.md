# AWS S3 Bucket Policy Does Not Use Allow With Not Principal

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Medium**         |

This policy validates that no S3 buckets have a policy that uses an `Effect:Allow` with a `NotPrincipal`. A configuration like this allows global access to that object with the specified actions to all entities except the specified `NotPrincipal`. It is very rare to need to use a `NotPrincipal`, and using a `NotPrincipal` with an `Effect:Allow` is almost always an incorrect configuration.

**Remediation**

To remediate this, remove the grant that is using a `NotPrincipal` with an `Effect:Allow`, either by removing the grant entirely or re-writing it correctly.

**Reference**

- AWS IAM Policy [NotPrincipal](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html) documentation
