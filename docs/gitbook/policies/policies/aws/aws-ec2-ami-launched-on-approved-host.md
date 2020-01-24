# AWS EC2 AMI Launched on Approved Host

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that an EC2 Instance was launched on a host approved for its AMI. This allows you to restrict what host an Instance is launched on based on its AMI, for example by specifying certain sensitive or critical AMI's are only to be launched on instances running on secured dedicated hosts.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, terminate any instances running on an unapproved host and relaunch them on an approved host.

**Reference**

- AWS EC2 [Dedicated Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/dedicated-instance.html) documentation
