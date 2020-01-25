# AWS Security Group Restricts Ingress On Administrative Ports

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Medium**         |

This policy validates that AWS Security Groups don't allow unrestricted inbound traffic on port 3389 or 22, ports commonly used for the remote access protocols RDP and SSH respectively.

Remote access protocols allow direct access and remote code execution on systems listening for those protocols if the protocol initiator can successfully authenticate. This has wide ranging security implications, even with strong password/authentication policies in place, and it is best practice to limit this access only to IP ranges it is necessary to open such access from for remote administration.

Ports 3389 and 22 are just two commonly used ports, similar precautions should be taken for any port being used for remote access protocols.

**Remediation**

To remediate this, implement least privilege policies for all security groups allowing unrestricted ingress on ports 3389 and 22. This could have wide ranging consequences if these rules are in use. Taking the actions listed below will break network connectivity for any resources in these VPC's using these overly permissive rules. It is highly recommended to first migrate these resources off into dedicated security groups with the minimum access necessary to perform their roles configured. VPC Flow Logging can help profile current network usage, and inform what how to build the least privilege rules necessary to not break any instances in these VPCs.

| Using the AWS Console                                                                                                                                                                                                                                                                                                                                                            |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Navigate to the [AWS VPC Security Group Console](https://console.aws.amazon.com/vpc/home#SecurityGroups:sort=groupId).                                                                                                                                                                                                                                                        |
| 2. Select the Security Group that you need to restrict inbound traffic on.                                                                                                                                                                                                                                                                                                       |
| 3. Select the "Inbound Rules" tab.                                                                                                                                                                                                                                                                                                                                               |
| 4. Select the "Edit rules" button.                                                                                                                                                                                                                                                                                                                                               |
| 5. If the rule is no longer need, select the "X" icon to delete it. Otherwise, under the "Source" column select "Custom" from the drop down and enter a valid IPV4 or IPV6 address that represents the minimum access necessary. For example, the public IP range of your company's office or the public IP address of a web service that will be accessing the given resources. |
| 6. Select the "Save rules" button.                                                                                                                                                                                                                                                                                                                                               |

| Using the AWS CLI                                                                                                                                                                                                                                                          |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. In order to delete security group rules, you must specify exactly the IP range, protocol, and port range of the existing rule you wish to delete. Run the following command for each overly permissive rule, inserting the exact values of the rule you wish to delete: |
| `aws ec2 revoke-security-group-ingress --group-id <security_group_id> --cidr <cidr_block> --protocol <TCP | UDP | ALL> --port <port_range>`                                                                                                                                |

**References**

- CIS AWS Benchmark 4.1 "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
- CIS AWS Benchmark 4.2 "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"
