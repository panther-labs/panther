# AWS EC2 Instance Running On Approved Host

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that EC2 Instances are only launched on approved hosts. This allows you to control what dedicated hosts your instances are launched on, and prevent instances from being launched on new non-approved dedicated hosts.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, terminate all EC2 Instances running on unapproved hosts and relaunch them on approved hosts.

**Reference**

- AWS EC2 [Dedicated Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/dedicated-instance.html) documentation
