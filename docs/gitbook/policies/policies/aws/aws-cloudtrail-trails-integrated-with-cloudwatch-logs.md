# AWS CloudTrail Sending To CloudWatch Logs

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **Info** | **Medium**         |

This policy validates that all CloudTrails have output being sent CloudWatch for real time analysis.

Real time log analysis is an important part of a mature security posture, and integrating with CloudWatch Logs is one way to accomplish this with AWS.

**Remediation**

To remediate this, configure each AWS CloudTrail trail identified in the report to send its logs to CloudWatch logs.

| Using the AWS Console                                                                                                     |
| :------------------------------------------------------------------------------------------------------------------------ |
| 1. Navigate to the [AWS CloudTrail Console](https://console.aws.amazon.com/cloudtrail/home#/configuration).               |
| 2. Select the trail you wish to enable CloudWatch logging for.                                                            |
| 3. Under the "CloudWatch Logs" header, select the "Configure" button.                                                     |
| 4. Specify the name of an existing CloudWatch Logs log group or a name for a new group then select the "Continue" button. |
| 5. Review the role and policy summary, then select the "Allow" button.                                                    |

| Using the AWS CLI                                                                                                                                                            |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. To integrate AWS CloudTrail with AWS CloudWatch Logs, run the following command:                                                                                          |
| `aws cloudtrail update-trail --name <trail_name> --cloudwatch-logs-log-grouparn <cloudtrail_log_group_arn> --cloudwatch-logs-role-arn <cloudtrail_cloudwatch_logs_role_arn>` |

**References**

- CIS AWS Benchmark 2.4 "Ensure CloudTrail trails are integrated with CloudWatch Logs"
- [Sending Events to CloudWatch Logs](https://amzn.to/2tMVU4a)
