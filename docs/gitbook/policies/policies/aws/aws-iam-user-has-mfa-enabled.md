# AWS IAM User Has MFA Enabled

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Medium**         |

This policy validates that all AWS IAM users with access to the AWS Console have Multi-Factor Authentication \(MFA\) enabled.

Enabling MFA can strengthen the integrity of the login process by providing a second factor. This ensures that if the password was leaked, a malicious actor could not login without the one time password from the MFA device.

**Remediation**

To remediate this, the IAM user should either have the AWS Login Profile removed, or have MFA enabled. To enable MFA for an IAM user, perform the following steps:

| Using the AWS Console                                                                                 |
| :---------------------------------------------------------------------------------------------------- |
| 1. Access the User tab of the [IAM console](https://console.aws.amazon.com/iam/home#/users).          |
| 2. Select the name of the non-compliant user.                                                         |
| 3. Select the "Security Credentials" tab.                                                             |
| 4. Select "Manage" next to "Assigned MFA Device Not assigned".                                        |
| 5. Follow the steps presented in the popup dialogue to complete the MFA device configuration process. |

| Using the AWS CLI                                                                                                                                                                                                                   |
| :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Run the following command to generate a virtual MFA device with a QR code seed. Note that this output file contains sensitive information and should be treated as such:                                                         |
| `aws iam create-virtual-mfa-device --virtual-mfa-device-name --outfile ./.png --bootstrap-method QRCodePNG`                                                                                                                         |
| 1. \(Alternate\) Run the following to generate a virtual MFA device with a base32 string seed instead of a QR code:                                                                                                                 |
| `aws iam create-virtual-mfa-device --virtual-mfa-device-name --outfile ./.txt --bootstrap-method Base32StringSeed`                                                                                                                  |
| 2. Use the out file generated in the previous step to seed the virtual MFA device by either scanning the QR code, or by entering the ARN of the user being assigned the MFA device and the key generated in the out file of step 1. |
| 3. Acquire two consecutive codes from the now seeded virtual MFA device, referred to below as and .                                                                                                                                 |
| 4. Run the following command. Note that the codes are time sensitive, and this command must be run very shortly after collecting them:                                                                                              |
| `aws iam enable-mfa-device --user-name --serial-number --authentication-code-1 --authentication-code-2`                                                                                                                             |

Alternatively, see the AWS documentation on having users managed their own MFA devices:

[https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html)

**References**

- CIS AWS benchmark 1.2 "Ensure multi-factor authentication \(MFA\) is enabled for all IAM users that have a console password."
- For documentation from AWS on enabling MFA, see:

  [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html)
