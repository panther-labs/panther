# AWS EC2 Set AMI to Private

#### Remediation Id

`EC2.SetAMIPrivate`

#### Description

Remediation that sets an AMI to private.

#### Resource Parameters

| Name        | Description                            |
| :---------- | :------------------------------------- |
| `AccountId` | The AWS Account Id of the EC2 instance |
| `Region`    | The AWS region of the EC2 instance     |
| `Id`        | The AMI Id                             |

#### References

- [EC2 Modify Image Attribute](https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-image-attribute.html)
