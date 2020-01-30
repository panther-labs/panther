# AWS KMS CMK Key Rotation Is Enabled

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that customer master keys \(CMKs\) have automatic key rotation enabled.

Regular key rotation is an important security best practice as it reduces the useful lifetime of potentially compromised keys. It also means if old key pairs are compromised, they will not pose a risk of data loss.

**Remediation**

To remediate this, enable CMK key rotation for each key listed in the report.

| Using the AWS Console                                                                                                    |
| :----------------------------------------------------------------------------------------------------------------------- |
| 1. Navigate to the customer managed key tab of the [AWS KMS Console](https://console.aws.amazon.com/kms/home#/kms/keys). |
| 2. Select the key where key rotation is not enabled.                                                                     |
| 3. Select the "Key rotation" tab.                                                                                        |
| 4. Check the "Automatically rotate this CMK every year" checkbox, then select the "Save" button.                         |

| Using the AWS CLI                                   |
| :-------------------------------------------------- |
| 1. Run the following command:                       |
| `aws kms enable-key-rotation --key-id <kms_key_id>` |

#### Impact

Automatic key rotation rotates the keys once every year. Automatically rotating keys will have no impact on your ability to decrypt data, as Amazon stores the previous keys for decryption purposes. Additionally, systems that refer to the KMS Key by ARN or Key ID do not need to be updated to point to the new key. There is a small cost of $1 per previous key stored per year, so with automatic key rotation enabled your AWS spend will increase by $1 per key per year, every year.

| Aspect              | Impact                        |
| :------------------ | :---------------------------- |
| AWS Cost            | \$1 increase per key per year |
| KMS Key Usability   | None                          |
| KMS Key Performance | None                          |

**References**

- CIS AWS Benchmark 2.8 "Ensure rotation for customer created CMKs is enabled"
- See the [AWS documentation](https://aws.amazon.com/kms/pricing/) for more details on pricing impact
