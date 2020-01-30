# AWS RDS Instance Has Auto Minor Version Upgrade Enabled

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that all RDS Instances have auto minor version upgrades enabled. Minor upgrades are normally not impactful to backwards compatibility, but may contain security updates. Enabling them to auto update is considered security best practice.

**Remediation**

To remediate this, enable auto minor version upgrade for each RDS Instance in the account.

**Reference**

- AWS RDS [Auto Minor Version Upgrade](https://aws.amazon.com/about-aws/whats-new/2018/12/amazon-rds-enhances-auto-minor-version-upgrades/) announcement
