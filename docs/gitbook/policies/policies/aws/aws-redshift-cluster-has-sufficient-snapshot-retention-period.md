# AWS Redshift Cluster Has Sufficient Snapshot Retention Period

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low**            |

This policy validates that all Redshift Clusters have an appropriate minimum snapshot retention period. Snapshot retention periods that are too low can cause data loss when issues with the Cluster data are not caught within the snapshot retention period and all good snapshots have aged out.

**Remediation**

To remediate this, configure each Redshift Cluster's snapshot retention period to be above the minimum.

**Reference**

- AWS Redshift Cluster [snapshot](https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-snapshots.html) documentation
