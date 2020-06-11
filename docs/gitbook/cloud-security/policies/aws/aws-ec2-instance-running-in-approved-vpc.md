# AWS EC2 Instance Running in Approved VPC

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that all EC2 Instances have been launched from within an approved VPC. This allows you to keep EC2 Instances in approved secure VPCs.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, terminate any EC2 Instances not launched within an approved VPC and re-launch them from within an approved VPC. This may require some other network configuration changes for anything communicating with that EC2 instance.
