# AWS DynamoDB Table Has Autoscaling Targets Configured

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Medium**         |

This policy builds on the AwS DynamoDB Table Has Autoscaling Enabled policy, and further validates that Auto Scaling is configured within appropriate minimum and maximum limits in accordance. This policy requires configuration before it can be enabled.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, update the Autoscaling targets of each DynamoDB table to be in line with your organizations accepted minimum and maximum.

**Reference**

- AWS DynamoDB [Auto Scaling](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/AutoScaling.html) documentation
