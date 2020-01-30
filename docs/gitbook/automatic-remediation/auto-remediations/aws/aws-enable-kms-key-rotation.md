# AWS Enable KMS Key Rotation

#### Remediation Id

`AWS.KMS.EnableKeyRotation`

#### Description

Remediation that enables key rotation for a KMS key

#### Resource Parameters

| Name        | Description                       |
| :---------- | :-------------------------------- |
| `AccountId` | The AWS Account Id of the KMS key |
| `Region`    | The AWS region of the KMS key     |
| `Id`        | The ID of the KMS key             |

#### References

- [https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)
