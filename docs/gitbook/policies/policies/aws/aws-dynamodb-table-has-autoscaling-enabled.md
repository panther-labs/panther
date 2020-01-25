# AWS DynamoDB Table Has Autoscaling Enabled

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that each DynamoDB Table has autoscaling enabled, if applicable. Autoscaling allows for the automatic increase in provisioned capacity, up to a configured limit, to address increases in demand.

**Remediation**

To remediate this, enable autoscaling with reasonable limits for each DynamoDB table.

**Reference**

- AWS DynamoDB [Auto Scaling](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/AutoScaling.html) documentation
