# AWS EC2 Volume Snapshot Is Encrypted

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that all snapshots of an EC2 Volume are encrypted. If an EC2 Volume is encrypted but its snapshot is not, anyone with access to the snapshot can restore it and get an unencrypted version of the volume.

**Remediation**

To remediate this, encrypt or delete all unencrypted volume snapshots.

**Reference**

- AWS [EBS Snapshots](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-creating-snapshot.html) documentation
