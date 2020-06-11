# AWS DynamoDB Table Has Encryption Enabled

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that each DynamoDB table has encryption enabled. Encryption can further protect data in the case of a DB compromise that exposes the data directly in the database.

**Remediation**

To remediate this, enable table encryption for each DynamoDB table.

**Reference**

- AWS DynamoDB [Encryption at Rest](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html) documentation
