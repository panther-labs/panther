# AWS Root Account Does Not Have Access Keys

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that no programmatic access keys exist for the root account.

The root account has the most privilege/access of any account, and should only be used when absolutely necessary. Programmatic access keys indicate regular and possibly unsupervised use. If programmatic access is needed for the root account for a specific use case, a key should be provisioned, the action carried out, then the key removed. All regular use should be delegated to lower privilege accounts.

**Remediation**

To remediate this, remove any access keys that exist under the root account. This can only be done as the root account account. You may wish to first disable the key, so if there are any critical services you were not aware of using the key you can re-enable the key while you move those services over to use keys from dedicated service accounts.

| Using the AWS Console                                                                                                                                                                                                                      |
| :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Log in with the root account, then go to the [root account security credentials tab](https://console.aws.amazon.com/iam/home#/security_credentials).                                                                                    |
| 2. Select "Access keys \(access key ID and secret access key\)" tab.                                                                                                                                                                       |
| 3. For each access key, under "Actions" select "Make Inactive"                                                                                                                                                                             |
| 4. Verify that no programmatic services have stopped working \(potentially waiting a few days for issues to be reported\).                                                                                                                 |
| 5. Go back to "Access keys \(access key ID and secret access key\)" tab in the root account. For each access key, under "Actions" select "Delete" then in the popup window select "Yes". As the popup warns, this action cannot be undone. |

| Using the AWS CLI                                          |
| :--------------------------------------------------------- |
| 1. This issue cannot currently be remediated from the CLI. |

**References**

- CIS AWS Benchmark 1.12 "Ensure no root account access key exists."
