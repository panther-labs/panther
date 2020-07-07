# Password Policy

#### Resource Type

`AWS.PasswordPolicy`

#### Resource ID Format

For Password Policy resources, the resource ID is constructed as such:

`[AccountId]::AWS.PasswordPolicy`

Example:

`123456789012::AWS.PasswordPolicy`

This allows you to differentiate between Password Policy resources across all AWS accounts you have linked by looking at the characters before the first colon.

#### Background

Password policies can be set on an AWS account to enforce complexity requirements. This resource models all of the [password policy options](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details) to ensure it is compliant with your internal requirements.

#### Fields

| Field                        | Type   | Description                                                                                                                                                    |
| :--------------------------- | :----- | :------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PasswordReusePrevention`    | `Int`  | The number of previous passwords AWS remembers and prevents users from re-using                                                                                |
| `AllowUsersToChangePassword` | `Bool` | Whether or not users can change their own password                                                                                                             |
| `AnyExist`                   | `Bool` | Indicates whether or not a password policy has been explicitly set in the account. If `false`, the resource will show the default values for the other fields. |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "AllowUsersToChangePassword": true,
    "AnyExist": true,
    "ExpirePasswords": true,
    "HardExpiry": null,
    "MaxPasswordAge": 90,
    "MinimumPasswordLength": 14,
    "Name": "AWS.PasswordPolicy",
    "PasswordReusePrevention": 24,
    "Region": "global",
    "RequireLowercaseCharacters": true,
    "RequireNumbers": true,
    "RequireSymbols": true,
    "RequireUppercaseCharacters": true,
    "ResourceId": "123456789012::AWS.PasswordPolicy",
    "ResourceType": "AWS.PasswordPolicy",
    "Tags": null,
    "TimeCreated": null
}
```
