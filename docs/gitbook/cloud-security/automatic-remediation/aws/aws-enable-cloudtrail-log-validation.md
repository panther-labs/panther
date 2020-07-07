# AWS Enable CloudTrail log validation

#### Remediation Id

`AWS.CloudTrail.EnableLogValidation`

#### Description

Remediation that enables log validation for an existing CloudTrail Trail.

#### Resource Parameters

| Name        | Description                     |
| :---------- | :------------------------------ |
| `AccountId` | The AWS Account Id of the trail |
| `Region`    | The AWS region of the trail     |
| `Name`      | The name of the trail           |

#### References

- [https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/update-trail.html)
