# AWS EC2 AMI Launched on Approved Instance Type

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that an EC2 Instance was launched with an instance type approved for its AMI. This allows you to restrict what instance type an Instance is launched with based on its AMI, for example by specifying certain sensitive or critical AMI's are only to be launched on instances running on at a high enough level of instance type.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, terminate all instances running on an unapproved instance type and relaunch them with an approved instance type.

**Reference**

- AWS EC2 [Instance Types](https://aws.amazon.com/ec2/instance-types/) documentation
