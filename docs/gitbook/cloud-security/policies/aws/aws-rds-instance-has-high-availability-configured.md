# AWS RDS Instance Has High Availability Configured

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that all RDS Instances have high availability configured. High availability can prevent the loss of service in the case of regional outages.

**Remediation**

To remediate this, enable and configure the `MutliAZ` setting for all RDS Instances

**Reference**

- AWS [High Availability for RDS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html) documentation
