# AWS Redshift Cluster Allows Version Upgrades

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that all Redshift clusters allow version upgrades automatically. Version upgrades often contain important security updates critical to keeping your infrastructure secure, and applying them automatically ensures your infrastructure stays up to date.

**Remediation**

To remediate this, enable the allow version upgrade setting for all redshift clusters.

**Reference**

- AWS [Redshift Cluster](https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html) documentation
