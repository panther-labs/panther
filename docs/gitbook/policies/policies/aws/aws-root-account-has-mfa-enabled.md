# AWS Root Account Has MFA Enabled

## AWS Root Account Using Hardware MFA

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Medium**         |

These policy validates that Multi Factor Authentication \(MFA\) is required for access to the root account, and that a hardware MFA device is in use.

The root account has the most privilege/access of any account, and should therefore be the most protected account. Enabling MFA mitigates much of the possibility of account compromise as both the password and the MFA device would need to be compromised at once for the account to be compromised. Hardware MFA is preferred as it is more difficult to compromise than a virtual MFA device.

**Remediation**

To remediate this, enable MFA for logins with the root account. This must be done from the AWS console, logged in as the root account.

| Using the AWS Console                                                                                                                                                                                       |
| :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Log in with the root account, then go to the root account security credentials tab at:                                                                                                                   |
| [https://console.aws.amazon.com/iam/home\#/security_credentials](https://console.aws.amazon.com/iam/home#/security_credentials)                                                                             |
| 2. Select the "Multi-factor authentication \(MFA\)" tab.                                                                                                                                                    |
| 3. Select the "Activate MFA" button.                                                                                                                                                                        |
| 4. Follow the setup steps displayed in the popup window to configure the MFA device. It is recommended to use hardware MFA for the root account if possible, but virtual MFA is preferred to no MFA at all. |

| Using the AWS CLI Tool                                                                       |
| :------------------------------------------------------------------------------------------- |
| 1. At this time this issue cannot be remediated with the AWS CLI tool or with AWS API calls. |

**References**

- CIS AWS Benchmark 1.13 "Ensure MFA is enabled for the "root" account".
- CIS AWS Benchmark 1.14 "Ensure hardware MFA is enabled for the "root" account".
