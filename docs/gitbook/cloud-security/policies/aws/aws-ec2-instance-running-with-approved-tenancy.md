# AWS EC2 Instance Running With Approved Tenancy

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that EC2 Instances are only launched with approved instance tenancy settings. This allows you to control what tenancy settings your instances are launched on, and prevent instances from being launched on dedicated \(or non-dedicated\) hosts.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, terminate all EC2 instances running with an unapproved instance tenancy setting and relaunch them with an approved instance tenancy.

**Reference**

- AWS EC2 [Dedicated Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/dedicated-instance.html) documentation
