# AWS CloudTrail Logs S3 Bucket Not Publicly Accessible

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Medium**         |

This policy validates that CloudTrail S3 buckets are not publicly accessible.

CloudTrail logs include detailed events of API activity in your AWS account. It is a security best practice to tightly control who has access to these logs, and making them publicly accessible could lead to accidental exposure of details about your environment.

**Remediation**

To remediate this, modify the associated S3 Bucket to not be publicly accessible.

| Using the AWS Console                                                                                                                          |
| :--------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Access the [AWS S3 Console](https://s3.console.aws.amazon.com/s3/home#).                                                                    |
| 2. Select the S3 bucket that you want to make not publicly accessible.                                                                         |
| 3. Select the "Permissions" tab.                                                                                                               |
| 4. Select the "Access Control List" tab.                                                                                                       |
| 5. Under the "Public access" header, select each row and in the popup menu uncheck all check boxes and then select the "Save" button.          |
| 6. Note that if you were relying on the public access to review these logs, a new more restricted access control list will need to be created. |

| Using the AWS CLI                                                                                                                                                                                                                                                                           |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1. Run the following command to ignore ACL's that grant public access on the given bucket:                                                                                                                                                                                                  |
| `aws s3api put-public-access-block --bucket <bucket_name> --public-access-block-configuration "{\"IgnorePublicAcls\": true}"`                                                                                                                                                               |
| 2. The AWS CLI command put-public-access-block has several parameters that can be set depending on how you intend to block public access. See the [AWS user documentation](https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html) for additional details. |

**References**

- CIS AWS Benchmark 2.3 "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible"
