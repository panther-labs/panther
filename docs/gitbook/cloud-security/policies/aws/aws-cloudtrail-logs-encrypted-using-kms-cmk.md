# AWS CloudTrail Logs Encrypted Using KMS CMK

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Medium**         |

This policy validates that AWS CloudTrails Logs are encrypted at rest with customer managed KMS CMKs.

CloudTrail logs include API level log events within your AWS account. It is a best security practice to encrypt these logs to reduce the chance they are exposed to unauthorized viewers to gain insight into your AWS environment.

**Remediation**

To remediate this, enable CloudTrail encryption using a KMS CMK.

| Using the AWS Console                                                                                                                                                     |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1. Access the trails tab of the [AWS CloudTrail Console](https://console.aws.amazon.com/cloudtrail/home#/configuration).                                                  |
| 2. Select the CloudTrail where you wish to enable encryption at rest.                                                                                                     |
| 3. Under the "Storage location" header, select the edit :pencil2: button.                                                                                                 |
| 4. Select the "Encrypt log files with SSE-KMS" radio button.                                                                                                              |
| 5. Select an existing key with an appropriate an appropriate KMS key policy to allow CloudTrail to encrypt the bucket, or select the "Create a new KMS key" radio button. |
| 6. If you selected "Create a new KMS key", name the key.                                                                                                                  |
| 7. Select the "Save" button                                                                                                                                               |

| Using the AWS CLI                                                                                                                   |
| :---------------------------------------------------------------------------------------------------------------------------------- |
| 1. Run the following command to attach the KMS key you intend to use for encryption to the CloudTrail trail:                        |
| `aws cloudtrail update-trail --name <trail_name> --kms-key-id <kms_key_id>`                                                         |
| 2. Be sure the KMS key policy grants CloudTrail permissions to describe KMS keys, encrypt with KMS keys, and decrypt with KMS keys. |

**References**

- CIS AWS Benchmark 2.7 "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"
- [Encrypting CloudTrail Log Files with AWS KMS–Managed Keys \(SSE-KMS\)](https://amzn.to/2ZqhL3h)

##
