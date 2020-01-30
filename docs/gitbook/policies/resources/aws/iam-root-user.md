---
description: Identity and Access Management (IAM) root User
---

# IAM Root User

#### Resource Type

`AWS.IAM.RootUser`

#### Resource ID Format

For IAM root users, the resource ID is the ARN.

`arn:aws:iam::123456789012:root`

#### Background

This resource represents a snapshot for an AWS root user account. This is largely similar to the `AWS.IAM.User` resource, but with a few added fields. Being a separate resource type also simplifies and optimizes writing policies which apply only to the root account, a common pattern.

#### Fields

| Field              | Type  | Description                                                                                        |
| :----------------- | :---- | :------------------------------------------------------------------------------------------------- |
| `CredentialReport` | `Map` | An AWS account credential report for this user. Implemented as a mapping of string keys to values. |
| `VirtualMFADevice` | `Map` | Contains the `EnableDate` and `SerialNumber` of the configured virtual MFA device, if one exists.  |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:iam::123456789012:root",
    "CredentialReport": {
        "ARN": "arn:aws:iam::123456789012:root",
        "AccessKey1Active": false,
        "AccessKey1LastRotated": "0001-01-01T00:00:00Z",
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
        "MfaActive": true,
        "PasswordEnabled": false,
        "PasswordLastChanged": "0001-01-01T00:00:00Z",
        "PasswordLastUsed": "2019-01-01T00:00:00Z",
        "PasswordNextRotation": "0001-01-01T00:00:00Z",
        "UserCreationTime": "2019-01-01T00:00:00Z",
        "UserName": "<root_account>"
    },
    "Id": "123456789012",
    "Name": "<root_account>",
    "Region": "global",
    "ResourceId": "arn:aws:iam::123456789012:root",
    "ResourceType": "AWS.IAM.RootUser",
    "Tags": null,
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "VirtualMFA": {
        "EnableDate": "2019-01-01T00:00:00Z",
        "SerialNumber": "arn:aws:iam::123456789012:mfa/root-virtual-mfa-device"
    }
}
```
