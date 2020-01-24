# AWS CloudTrail Has Log Validation Enabled

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that AWS CloudTrails have log file validation enabled.

Log file validation digitally signs the CloudTrail Log to ensure it has not been tampered with. Due to the sensitive nature of CloudTrail logs, and their value in forensic and post-incident investigations, it is very valuable to know they have not been tampered with.

**Remediation**

To remediate this, enable log validation for the CloudTrail Log in the report.

| Using the AWS Console                                                                                   |
| :------------------------------------------------------------------------------------------------------ |
| 1. Access the [AWS CloudTrail Console](https://console.aws.amazon.com/cloudtrail/home?#/configuration). |
| 2. Select the CloudTrail you wish to enable log validation for.                                         |
| 3. Under the " Storage location" header, select the edit :pencil2: button.                              |
| 4. Next to "Enable log file validation" select the "Yes" radio button then select the "Save" button.    |

| Using the AWS CLI                                                              |
| :----------------------------------------------------------------------------- |
| 1. Run the following command:                                                  |
| `aws cloudtrail update-trail --name <trail_name> --enable-log-file-validation` |

**References**

- CIS AWS Benchmark 2.2 "Ensure CloudTrail log file validation is enabled"
