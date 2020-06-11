---
description: Identity and Access Management (IAM) User
---

# IAM User

#### Resource Type

`AWS.IAM.User`

#### Resource ID Format

For IAM Users, the resource ID is the ARN.

`arn:aws:iam::123456789012:user/example-user`

#### Background

This resource represents a snapshot for an AWS IAM user.

#### Fields

| Field                | Type   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| :------------------- | :----- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CredentialReport`   | `Map`  | This is a recent credential report generated for this user, including information such as whether password login is enabled, the last time access keys were rotated, whether MFA is required for logins, etc. `GeneratedDate` indicates at what time the credential report was generated, it is only generated approximately once every four hours and re-used in between. This is due to limitations in the AWS API. If a field requires a timestamp but was returned empty or as `no_information` or `N/A` or `not_supported` by AWS, it defaults to `0001-01-01T00:00:00Z`. Be sure to write policies accordingly. |
| `InlinePolicies`     | `Map`  | A mapping of inline policy names to their policy documents                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `ManagedPolicyNames` | `List` | AWS managed policies assigned to the user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/example-user",
    "CredentialReport": {
        "ARN": "arn:aws:iam::123456789012:user/example-user",
        "AccessKey1Active": true,
        "AccessKey1LastRotated": "2019-01-01T00:00:00Z",
        "AccessKey1LastUsedDate": "0001-01-01T00:00:00Z",
        "AccessKey1LastUsedRegion": "N/A",
        "AccessKey1LastUsedService": "N/A",
        "AccessKey2Active": false,
        "AccessKey2LastRotated": "0001-01-01T00:00:00Z",
        "AccessKey2LastUsedDate": "0001-01-01T00:00:00Z",
        "AccessKey2LastUsedRegion": "N/A",
        "AccessKey2LastUsedService": "N/A",
        "Cert1Active": false,
        "Cert1LastRotated": "0001-01-01T00:00:00Z",
        "Cert2Active": false,
        "Cert2LastRotated": "0001-01-01T00:00:00Z",
        "MfaActive": false,
        "PasswordEnabled": true,
        "PasswordLastChanged": "2019-01-01T00:00:00Z",
        "PasswordLastUsed": "2019-01-01T00:00:00Z",
        "PasswordNextRotation": "2019-12-01T00:00:00Z",
        "UserCreationTime": "2019-01-01T00:00:00Z",
        "UserName": "example-user"
    },
    "Groups": [
        {
            "Arn": "arn:aws:iam::123456789012:group/example-group",
            "CreateDate": "2019-01-01T00:00:00Z",
            "GroupId": "1111",
            "GroupName": "example-group",
            "Path": "/"
        }
    ],
    "Id": "1111",
    "InlinePolicies": null,
    "ManagedPolicyNames": [
        "example-policy"
    ],
    "Name": "example-user",
    "PasswordLastUsed": "2019-01-01T00:00:00Z",
    "Path": "/",
    "PermissionsBoundary": null,
    "Region": "global",
    "ResourceId": "arn:aws:iam::123456789012:user/example-user",
    "ResourceType": "AWS.IAM.User",
    "Tags": null,
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "VirtualMFA": {
        "EnableDate": "2019-01-01T00:00:00Z",
        "SerialNumber": "arn:aws:iam::123456789012:mfa/example-mfa"
    }
}
```
