# AWS Disable RDS Instance Public Access

#### Remediation Id

`AWS.RDS.DisableInstancePublicAccess`

#### Description

Remediation that disables public access for an RDS instance

#### Resource Parameters

| Name        | Description                            |
| :---------- | :------------------------------------- |
| `AccountId` | The AWS Account Id of the RDS instance |
| `Region`    | The AWS region of the RDS instance     |
| `Id`        | The DB Instance Id                     |

#### References

- [https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-instance.html](https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-instance.html)
