---
description: Identity and Access Management (IAM) Group
---

# IAM Group

#### Resource Type

`AWS.IAM.Group`

#### Resource ID Format

For IAM Groups, the resource ID is the ARN.

`arn:aws:iam::123456789012:group/example-group`

#### Background

An IAM group is a collection of IAM users. Groups let you specify permissions for multiple users, which can make it easier to manage the permissions for those users.

#### Fields

| Field                | Type     | Description                                                             |
| :------------------- | :------- | :---------------------------------------------------------------------- |
| `Users`              | `List`   | The IAM User members of the group                                       |
| `InlinePolicies`     | `Map`    | A mapping of inline policies keyed by PolicyName to the Policy Document |
| `ManagedPolicyNames` | `List`   | The AWS Managed Policy names attached to the group                      |
| `Path`               | `String` | The path to the group                                                   |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:iam::123456789012:group/example-group",
    "Id": "111",
    "InlinePolicies": null,
    "ManagedPolicyARNs": [
        "arn:aws:iam::aws:policy/IAMUserChangePassword"
    ],
    "Name": "example-group",
    "Path": "/",
    "Region": "global",
    "ResourceId": "arn:aws:iam::123456789012:group/example-group",
    "ResourceType": "AWS.IAM.Group",
    "Tags": null,
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "Users": [
        {
            "Arn": "arn:aws:iam::123456789012:user/example-user",
            "CreateDate": "2019-01-01T00:00:00Z",
            "PasswordLastUsed": "2019-01-01T00:00:00Z",
            "Path": "/",
            "PermissionsBoundary": null,
            "Tags": null,
            "UserId": "2222",
            "UserName": "example-user"
        }
    ]
}
```
