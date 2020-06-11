# GuardDuty Detector

#### Resource Type

`AWS.GuardDuty.Detector`

#### Resource ID Format

For GuardDuty Detector resources, the resource ID is constructed as such:

`[AccountId]:[region]:AWS.GuardDuty.Detector`

Example:

`123456789012:us-west-2:AWS.GuardDuty.Detector`

This allows you to differentiate between GuardDuty Detector resources across all AWS accounts you have linked by looking at the characters before the first colon, and to differentiate between GuardDuty Detector resources within an account by looking at the characters between the first and second colon.

#### Background

This resource represents a snapshot of an AWS GuardDuty detector.

#### Fields

| Field    | Type     | Description                                                                |
| :------- | :------- | :------------------------------------------------------------------------- |
| `Master` | `Map`    | The master GuardDuty detector this account is subscribed to, if one exists |
| `Status` | `String` | Indicates whether the detector is `ENABLED` or `DISABLED`                  |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "FindingPublishingFrequency": "SIX_HOURS",
    "Id": "12a12345b12345c12ab12a1a1ab1a1ab1",
    "Master": {
        "AccountId": "99a12345b12345c12ab12a1a1ab1a1ab1",
        "InvitationId": "11111111111111",
        "InvitedAt": "2019",
        "RelationshipStatus": "active"
    },
    "Region": "eu-central-1",
    "ResourceId": "123456789012:eu-central-1:AWS.GuardDuty.Detector",
    "ResourceType": "AWS.GuardDuty.Detector",
    "ServiceRole": "arn:aws:iam::123456789012:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
    "Status": "ENABLED",
    "Tags": {
        "KeyName1": "Value1"
    },
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "UpdatedAt": "2019-01-01T00:00:00.000Z"
}
```
