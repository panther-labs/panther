# AWS Network ACL Restricts SSH

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that all EC2 Network ACLs are restricting inbound SSH connections in some fashion. SSH access should only be granted from protected/approved network CIDR ranges, not exposed to the world at large.

**Remediation**

To remediate this, modify the IP permissions ingress of the EC2 Network ACL to restrict the source IP range for all rules that allow SSH to a trusted range.

**Reference**

- AWS Network ACL [Rules](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html#nacl-rules) documentation
