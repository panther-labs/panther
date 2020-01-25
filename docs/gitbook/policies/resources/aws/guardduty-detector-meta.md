# GuardDuty Detector Meta

#### Resource Type

`AWS.GuardDuty.Detector.Meta`

#### Resource ID Format

For GuardDuty Detector Meta resources, the resource ID is constructed as such:

`[AccountId]::AWS.GuardDuty.Detector.Meta`

Example:

`123456789012::AWS.GuardDuty.Detector.Meta`

This allows you to differentiate between GuardDuty Detector Meta resources across all AWS accounts you have linked by looking at the characters before the first colon.

#### Background

This resource represents some account wide information about configured AWS GuardDuty detector.

#### Fields

| Field       | Type  | Description                                                                                                                          |
| :---------- | :---- | :----------------------------------------------------------------------------------------------------------------------------------- |
| `Detectors` | `Map` | A list of the resource IDs of GuardDuty detectors in the account, useful for determining what regions have GuardDuty enabled in them |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Detectors": [
        "123456789012:us-west-2:AWS.GuardDuty.Detector"
    ],
    "Region": "global",
    "ResourceId": "123456789012::AWS.GuardDuty.Detector.Meta",
    "ResourceType": "AWS.GuardDuty.Detector.Meta",
    "Tags": null,
    "TimeCreated": null
}
```
