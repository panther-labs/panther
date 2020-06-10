# AWS EC2 Instance Running on Approved AMI

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that each EC2 Instance is running on an approved AMI. This prevents instances from being launched from unexpected AMI's, for example AMI's being launched by an attacker for crypto currency mining.

From an operational perspective, this can also ensure your environment is only running AMI's approved by architectural design groups, perhaps for consistency or licensing .

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, terminate any instances running with an unapproved AMI. Those instances may need to be replaced with other instances, launched from approved AMIs.

**Reference**

- AWS EC2 [AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html) documentation
