# AWS EC2 AMI Launched With Approved Tenancy

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that an EC2 Instance was launched with a tenancy approved for its AMI. This allows you to restrict what tenancy an Instance is launched with based on its AMI, for example by specifying certain sensitive or critical AMI's are only launched on instances with a`dedicated` tenancy.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, terminate any instances running with an incorrect tenancy and re-launch them with the appropriate tenancy setting.

**Reference**

- AWS EC2 [Dedicated Instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/dedicated-instance.html) documentation
