---
description: Identity and Access Management (IAM) Role
---

# IAM Role

#### Resource Type

`AWS.IAM.Role`

#### Resource ID Format

For IAM Roles, the resource ID is the ARN.

`arn:aws:iam::123456789012:role/example-role`

#### Background

An IAM role is an IAM identity that you can create in your account that has specific permissions. AWS Users and services can then assume the role in order to gain those permissions. An IAM role is similar to an IAM user, in that it is an AWS identity with permission policies that determine what the identity can and cannot do in AWS.

#### Fields

| Type                       | Description |                                                                                                                                                                               |
| :------------------------- | :---------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AssumeRolePolicyDocument` | `String`    | An IAM Policy dictating which resources can assume this role                                                                                                                  |
| `Description`              | `String`    | A description of the role that you provide.                                                                                                                                   |
| `MaxSessionDuration`       | `Int`       | The maximum session duration \(in seconds\) for the specified role.                                                                                                           |
| `Path`                     | `String`    | The path to the role.                                                                                                                                                         |
| `PermissionsBoundary`      | `Map`       | The ARN and Type of the policy used to set the [permissions boundary](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachedPermissionsBoundary.html) for the role. |
| `InlinePolicies`           | `Map`       | A mapping of inline policies keyed by PolicyName with the value of the Policy Document                                                                                        |
| `ManagedPolicyNames`       | `List`      | The AWS Managed Policy names attached to the role.                                                                                                                            |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:iam::123456789012:role/example-role",
    "AssumeRolePolicyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\",\"Condition\":{\"Bool\":{\"aws:MultiFactorAuthPresent\":\"true\"}}}]}",
    "Description": null,
    "Id": "1111",
    "InlinePolicies": null,
    "ManagedPolicyNames": [
        "example-policy-1",
        "example-policy-2"
    ],
    "MaxSessionDuration": 3600,
    "Name": "example-role",
    "Path": "/",
    "PermissionsBoundary": null,
    "Region": "global",
    "ResourceId": "arn:aws:iam::123456789012:role/example-role",
    "ResourceType": "AWS.IAM.Role",
    "Tags": null,
    "TimeCreated": "2019-01-01T00:00:00.000Z"
}
```
