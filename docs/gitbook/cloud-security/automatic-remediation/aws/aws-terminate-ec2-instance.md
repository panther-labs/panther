# AWS Terminate EC2 Instance

#### Remediation Id

`AWS.EC2.TerminateInstance`

#### Description

Remediation that terminates an EC2 instance.

#### Resource Parameters

| Name        | Description                            |
| :---------- | :------------------------------------- |
| `AccountId` | The AWS Account Id of the EC2 instance |
| `Region`    | The AWS region of the EC2 instance     |
| `Id`        | The Instance Id                        |

#### References

- [https://docs.aws.amazon.com/cli/latest/reference/ec2/terminate-instances.html](https://docs.aws.amazon.com/cli/latest/reference/ec2/terminate-instances.html)
