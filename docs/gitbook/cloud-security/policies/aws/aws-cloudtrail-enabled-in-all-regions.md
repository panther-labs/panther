# AWS CloudTrail Is Enabled In All Regions

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Medium**         |

This policy validates that CloudTrail is enabled in all regions.

CloudTrail provides detailed logging of actions taken by AWS users, roles, and services from the AWS console, CLI tool, and various SDK's and API's. These logs provide information that is invaluable to evaluating the security of an AWS environment, and for monitoring in real time for threats and malicious activity occurring in the environment.

**Remediation**

To remediate this, individually enable CloudTrail in each region or a multi-region trail is enabled.

| Using the AWS Console                                                                                                                                                                                                                  |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Navigate to the [AWS CloudTrail Console](https://console.aws.amazon.com/cloudtrail/home?#/configuration).                                                                                                                           |
| 2. Select the "Create trail" button.                                                                                                                                                                                                   |
| 3. Input a name for the trail.                                                                                                                                                                                                         |
| 4. Ensure that next to "Apply trail to all regions" the "Yes" radio button is selected if you wish to create one trail that monitors all regions. If you prefer to configure a separate region for each trail, select the "No" button. |
| 5. Under the "Management events" header, ensure that next to "Read/Write events" the "All" radio button is selected.                                                                                                                   |
| 6. Optionally, under the "Data events" header configure additional logging.                                                                                                                                                            |
| 7. Under the "Storage location"header, select an existing S3 bucket to write logs to or configure a new one.                                                                                                                           |
| 8. Optionally, under the "Storage location" header in the "Advanced" section, configure additional settings. Panther recommends enabling "Encrypt log files with SSE-KMS" and "Enable log file validation".                            |
| 9. Select the "Create" button.                                                                                                                                                                                                         |

| Using the AWS CLI                                                                                                                                                                            |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. There are many configuration settings that can be set for CloudTrail, run the following command to configure the basic settings that runpanther recommends:                               |
| `aws cloudtrail create-trail --name <trail_name> --s3-bucket-name <bucket_name> --is-multi-region-trail --include-global-service-events --enable-log-file-validation --kms-key-id <kms_arn>` |

**References**

- CIS AWS Benchmark 2.1 "Ensure CloudTrail is enabled in all regions"
- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
- [Creating a Trail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html)
