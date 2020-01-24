# CloudTrail Meta

#### Resource Type

`AWS.CloudTrail.Meta`

#### Resource ID Format

For CloudTrail Meta resources, the resource ID is constructed as such:

`[AccountId]::AWS.CloudTrail.Meta`

Example:

`123456789012::AWS.CloudTrail.Meta`

This allows you to differentiate between CloudTrail Meta resources across all AWS accounts you have linked to Panther by looking at the characters before the first colon.

#### Background

This resource represents metadata on AWS CloudTrails for an entire account. Every time an account snapshot is taken, exactly one `AWS.CloudTrail.Meta` resource will be generated.

#### Fields

| Field                  | Type   | Description                                                                                                                                                                            |
| :--------------------- | :----- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Trails`               | `List` | A list of the ARNs of every trail in the account. Used to check for the existence of certain trails, the count of trails in an account, and the presence of trails in certain regions. |
| `GlobalEventSelectors` | `List` | The collection of management and data event settings across each CloudTrail in each region.                                                                                            |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "GlobalEventSelectors": [
        {
            "DataResources": null,
            "IncludeManagementEvents": true,
            "ReadWriteType": "All"
        }
    ],
    "Name": "AWS.CloudTrail.Meta",
    "Region": "global",
    "ResourceId": "123456789012::AWS.CloudTrail.Meta",
    "ResourceType": "AWS.CloudTrail.Meta",
    "Tags": null,
    "TimeCreated": null,
    "Trails": [
        "arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-east-1-1",
        "arn:aws:cloudtrail:us-east-1:123456789012:trail/trail-east-1-2",
        "arn:aws:cloudtrail:us-west-2:123456789012:trail/trail-west-2-1",
        "arn:aws:cloudtrail:us-west-1:123456789012:trail/other-trail"
    ]
}
```
