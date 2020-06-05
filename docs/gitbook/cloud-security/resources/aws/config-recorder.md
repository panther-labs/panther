# Config Recorder

#### Resource Type

`AWS.Config.Recorder`

#### Resource ID Format

For Config Recorder resources, the resource ID is constructed as such:

`[AccountId]:[region]:AWS.CloudTrail.Meta`

Example:

`123456789012:us-west-2:AWS.Config.Recorder`

This allows you to differentiate between Config Recorder resources across all AWS accounts you have linked by looking at the characters before the first colon, and to differentiate between Config Recorder resources within an account by looking at the characters between the first and second colon.

#### Background

This resource represents an AWS Config Recorder in a single region.

#### Fields

| Field            | Description                                                                                             |
| :--------------- | :------------------------------------------------------------------------------------------------------ |
| `RecordingGroup` | Settings on the configuration recorder's group                                                          |
| `Status`         | Indicates whether this recorder is enabled, its name, and the most recent timestamps of certain events. |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Name": "default",
    "RecordingGroup": {
        "AllSupported": true,
        "IncludeGlobalResourceTypes": true,
        "ResourceTypes": null
    },
    "Region": "us-west-2",
    "ResourceId": "123456789012:us-west-2:AWS.Config.Recorder",
    "ResourceType": "AWS.Config.Recorder",
    "RoleARN": "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
    "Status": {
        "LastErrorCode": null,
        "LastErrorMessage": null,
        "LastStartTime": "2019-01-01T00:00:00Z",
        "LastStatus": "SUCCESS",
        "LastStatusChangeTime": "2019-01-01T00:00:00Z",
        "LastStopTime": null,
        "Name": "default",
        "Recording": true
    },
    "Tags": null,
    "TimeCreated": null
}
```
