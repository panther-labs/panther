# AWS Enable RDS Instance Auto Minor Version Upgrade

#### Remediation Id

`AWS.RDS.EnableAutoMinorVersionUpgrade`

#### Description

Remediation that enables automatic minor version upgrade for an RDS instance

#### Resource Parameters

| Name        | Description                            |
| :---------- | :------------------------------------- |
| `AccountId` | The AWS Account Id of the RDS instance |
| `Region`    | The AWS region of the RDS Instance     |
| `Id`        | The RDS instance identifier            |

#### Additional Parameters

<table>
  <thead>
    <tr>
      <th style="text-align:left">Name</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><code>ApplyImmediately</code>
      </td>
      <td style="text-align:left">
        <p>Boolean that indicates whether the modifications is asynchronously applied
          as soon as possible, regardless of the PreferredMaintenanceWindow setting
          for the DB instance.</p>
        <p>If this parameter is set to <code>false</code>, changes to the DB instance
          are applied during the next maintenance window.</p>
      </td>
    </tr>
  </tbody>
</table>#### References

- [https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-instance.html](https://docs.aws.amazon.com/cli/latest/reference/rds/modify-db-instance.html)
