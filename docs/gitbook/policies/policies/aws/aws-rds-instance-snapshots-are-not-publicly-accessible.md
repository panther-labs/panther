# AWS RDS Instance Snapshots Are Not Publicly Accessible

| Risk         | Remediation Effort |
| :----------- | :----------------- |
| **Critical** | **Low**            |

This policy validates that no RDS Instance snapshots are publicly restorable. A publicly restorable RDS Instance snapshot means that anyone with an AWS account can access the contents of that snapshot.

**Remediation**

To remediate this delete all publicly accessible RDS Instance snapshots. Alternatively, modify the `restore` attribute on the snapshot to not include the value `all`.
