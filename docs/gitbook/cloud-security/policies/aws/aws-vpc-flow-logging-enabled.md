# AWS VPC Flow Logging Enabled

This policy validates that AWS VPCs \(Virtual Private Clouds\) have network flow logging enabled.

| Risk       | Remediation Effort |
| :--------- | :----------------- |
| **Medium** | **Low**            |

Flow logs provide layer 3 network traffic telemetry to-and-from any resource within a VPC. This is considered a security best practice as it allows for the monitoring and detection of potentially malicious traffic.

Flow logs can be configured either on a single network interface, a subnet, or an entire VPC. Filters can also be used to limit the logs based on attributes, which in a busy production network is often necessary. Logs can be stored in either CloudWatch Logs or S3.

**Remediation**

Enable Flow Logging for the VPC failing this policy.

| Using the AWS Console                                                                                                    |
| :----------------------------------------------------------------------------------------------------------------------- |
| 1. Navigate to the "Your VPCs" tab on the [VPC Dashboard](https://console.aws.amazon.com/vpc/home#vpc).                  |
| 2. Select the VPC where flow logging is not enabled.                                                                     |
| 3. Select the Flow Logs tab.                                                                                             |
| 4. Select the "Create flow log" button.                                                                                  |
| 5. Set the filter to "Accept", "Reject", or "All" depending on the level of logging desired.                             |
| 6. Set the destination log group to "default-vpc-flow-logs".                                                             |
| 7. Select the IAM role to use for publishing flow logs \(or create one with the Set Up Permissions link on the bottom\). |
| 6. Select the "Create" button.                                                                                           |

| Using the AWS CLI                                                                                                                                                                                                                           |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1. To deliver Flow Logs to a CloudWatch Log Group, run the following command:                                                                                                                                                               |
| `aws ec2 create-flow-logs --traffic-type <ACCEPT | REJECT | ALL> --resource-type VPC --resource-ids <vpc_id> --log-destination-type cloud-watch-logs --log-group-name "default-vpc-flow-logs" --deliver-logs-permission-arn <iam_role_arn>` |
| 2. Alternatively, to deliver Flow Logs to an S3 bucket, run the following command:                                                                                                                                                          |
| `aws ec2 create-flow-logs --traffic-type <ACCEPT | REJECT | ALL> --resource-type VPC --resource-ids <vpc_id> --log-destination-type s3 --log-destination <s3_arn>`                                                                          |

#### Impact

Enabling flow logging will generate additional CloudWatch events, which have an associated cost. There will be no impact to VPC usability or performance.

| Aspect          | Impact                                                                                                                                      |
| :-------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| AWS Cost        | Dependent on scope, see the [AWS documentation](https://aws.amazon.com/cloudwatch/pricing#Example_4_-_Monitoring_VPC_flow_logs) for details |
| VPC Performance | None                                                                                                                                        |
| VPC Usability   | None                                                                                                                                        |

**References**

- CIS AWS Benchmark 2.9: "Ensure VPC flow logging is enabled in all VPCs"
- [AWS VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [AWS EC2 CLI Documentation](https://docs.aws.amazon.com/cli/latest/reference/ec2/create-flow-logs.html)
- [AWS EC2 Console Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-cwl.html#flow-logs-cwl-create-flow-log)
- [AWS Pricing Information](https://aws.amazon.com/cloudwatch/pricing#Example_4_-_Monitoring_VPC_flow_logs)
