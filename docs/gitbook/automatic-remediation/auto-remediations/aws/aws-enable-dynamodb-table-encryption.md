# AWS Enable DynamoDB Table Encryption

#### Remediation Id

`AWS.DDB.EncryptTable`

#### Description

Remediation that enables Server Side Encryption for a DynamoDB table.

#### Resource Parameters

| Name        | Description                              |
| :---------- | :--------------------------------------- |
| `AccountId` | The AWS Account Id of the DynamoDB table |
| `Region`    | The AWS region of the DynamoDB table     |
| `Name`      | The name of the DynamoDB table           |

#### References

- [https://docs.aws.amazon.com/cli/latest/reference/dynamodb/update-table.html](https://docs.aws.amazon.com/cli/latest/reference/dynamodb/update-table.html)
- [https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html)
