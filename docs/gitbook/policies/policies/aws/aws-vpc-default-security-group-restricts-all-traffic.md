# AWS VPC Default Security Group Restricts All Traffic

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **High**           |

This policy validates that the default Security Group for a given AWS VPC restricts all inbound and outbound traffic.

The principle of least privilege dictates that all traffic should be blocked unless explicitly needed, and it's recommended to create security groups for all categorizations of inbound/outbound traffic flows. Ensuring the default security group blocks all traffic enables this behavior by forcing all new EC2 instances to be moved off the default security group if they require internet access.

**Remediation**

To remediate this, delete all inbound and outbound rules for all default security groups found in the report.

This could have wide ranging consequences if these default security groups are in use. Taking the actions listed below will break all network connectivity for any resources in these VPC's still using the default security group.

It is highly recommended to first migrate these resources off into dedicated security groups with the minimum access necessary to perform their roles configured. VPC Flow Logging can help profile current network usage, and inform what how to build the least privilege rules necessary to not break any instances in these VPCs.

| Using the AWS Console                                                                                                     |
| :------------------------------------------------------------------------------------------------------------------------ |
| 1. Navigate to the [AWS VPC Security Group Console](https://console.aws.amazon.com/vpc/home#SecurityGroups:sort=groupId). |
| 2. Select the Security Group that you need to restrict traffic on \(it will be one of the ones with the name "default"\). |
| 3. Select the "Inbound Rules" tab.                                                                                        |
| 4. Select the "Edit rules" button.                                                                                        |
| 5. Select the "X" icon next to each rule to delete it.                                                                    |
| 6. Select the "Save rules" button                                                                                         |
| 7. Select the "Outbound Rules" tab, and then repeat the actions taken in steps 4 through 6.                               |

| Using the AWS CLI                                                                                                                                                                                                                                                |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. In order to delete security group rules, you must specify exactly the IP range, protocol, and port range of the existing rule you wish to delete. Run the following command for each inbound rule, inserting the exact values of the rule you wish to delete: |
| `aws ec2 revoke-security-group-ingress --group-id <security_group_id> --cidr <cidr_block> --protocol <TCP | UDP | ALL> --port <port_range>`                                                                                                                      |
| 2. Run the following command for each outbound rule, making the appropriate replacements as above:                                                                                                                                                               |
| `aws ec2 revoke-security-group-egress --group-id <security_group_id> --cidr <cidr_block> --protocol <TCP | UDP | ALL> --port <port_range>`                                                                                                                       |

**References**

- CIS AWS Benchmark 4.3 "Ensure the default security group of every VPC restricts all traffic"
