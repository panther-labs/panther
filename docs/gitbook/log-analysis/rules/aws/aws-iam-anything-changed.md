# AWS IAM Anything Changed

This rule monitors for any changes to IAM entities in your environment.

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **Info** | **Low**            |

IAM Entities are typically the ultimate designator's of permission and access in an AWS environment. Changes to these entities should be carefully monitored and approved. This broad rule can give an indication of how dynamic a given IAM environment is.

**Remediation**

Verify that the IAM changes are planned and were approved, if not revert the changes and modify permissions so this does not happen again.
