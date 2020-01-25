# AWS Customer Owned AMI Is Private

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that all AMI's owned by the customer account are set to private. This prevents adversaries from being able to launch these AMI's and gain information about the configuration of your environment, and possible gain access to sensitive information configured within the AMI.

**Remediation**

To remediate this, change the launch permission attribute of the image from the AWS [EC2 Image panel.](https://us-west-2.console.aws.amazon.com/ec2/home?Images:sort=name)

**References**

- AWS EC2 [Sharing AMI's](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-intro.html) Documentation
