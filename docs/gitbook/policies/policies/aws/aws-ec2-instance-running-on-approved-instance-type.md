# AWS EC2 Instance Running on Approved Instance Type

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that each EC2 Instance is running on an approved instance type. This prevents instances from being launched on unexpected instance types, for example extremely large instance types being launched by an attacker for crypto currency mining.

From an operational perspective, this can also ensure your environment is only running instance types approved by architectural design groups, perhaps for budgeting reasons.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, terminate all instances running on an unapproved instance type and relaunch them with an approved instance type.

**Reference**

- AWS EC2 [Instance Types](https://aws.amazon.com/ec2/instance-types/) documentation
