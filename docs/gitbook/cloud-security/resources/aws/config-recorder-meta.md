# Config Recorder Meta

#### Resource Type

`AWS.Config.Recorder.Meta`

#### Resource ID Format

For Config Recorder Meta resources, the resource ID is constructed as such:

`[AccountId]::AWS.Config.Recorder.Meta`

Example:

`123456789012::AWS.Config.Recorder.Meta`

This allows you to differentiate between Config Recorder Meta resources across all AWS accounts you have linked by looking at the characters before the first colon.

#### Background

This resource tracks metadata on all AWS Config Recorders within an AWS account. Best practice dictates that a configuration recorder should be setup in each region, and at least one of them should track all resources.

#### Fields

| Field                 | Type   | Description                                                                                  |
| :-------------------- | :----- | :------------------------------------------------------------------------------------------- |
| `GlobalRecorderCount` | `Int`  | The number of AWS Config resources configured to monitor global resources within the account |
| `Recorders`           | `List` | A list of the resource IDs of all recorders in the account                                   |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "GlobalRecorderCount": 1,
    "Name": "AWS.Config.Recorder.Meta",
    "Recorders": [
        "123456789012:us-west-2:AWS.Config.Recorder"
    ],
    "Region": "global",
    "ResourceId": "123456789012::AWS.Config.Recorder.Meta",
    "ResourceType": "AWS.Config.Recorder.Meta",
    "Tags": null,
    "TimeCreated": null
}

```
