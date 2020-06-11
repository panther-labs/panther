# CloudFormation Stack

#### Resource Type

`AWS.CloudFormation.Stack`

#### Resource ID Format

For CloudFormation Stacks, the resource ID is the ARN.

`arn:aws:cloudformation:ap-northeast-2:123456789012:stack/example-stack/11111111`

#### Background

A stack is a collection of AWS resources that you can manage as code within a template.

#### Fields

<table>
  <thead>
    <tr>
      <th style="text-align:left">Field</th>
      <th style="text-align:left">Type</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><code>Capabilities</code>
      </td>
      <td style="text-align:left"><code>List</code>
      </td>
      <td style="text-align:left">Certain capabilities required in order for AWS CloudFormation to create
        the stack.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>ChangeSetId</code>
      </td>
      <td style="text-align:left"><code>String</code>
      </td>
      <td style="text-align:left">The ID of the change set</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>DeletionTime</code>
      </td>
      <td style="text-align:left"><code>Time</code>
      </td>
      <td style="text-align:left">The time the stack was deleted.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>Description</code>
      </td>
      <td style="text-align:left"><code>String</code>
      </td>
      <td style="text-align:left">A user-defined description associated with the stack.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>DisableRollback</code>
      </td>
      <td style="text-align:left"><code>Bool</code>
      </td>
      <td style="text-align:left">
        <p>Boolean to enable or disable rollback on stack creation failures: <code>true</code>disables
          rollback,</p>
        <p><code>false</code> enables rollback.</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><code>DriftInformation</code>
      </td>
      <td style="text-align:left"><code>Map</code>
      </td>
      <td style="text-align:left"><a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_StackDriftInformation.html">Information</a> on
        whether a stack&apos;s actual configuration differs from its expected configuration</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>EnableTerminationProtection</code>
      </td>
      <td style="text-align:left"><code>Bool</code>
      </td>
      <td style="text-align:left">Whether termination protection is enabled for the stack.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>LastUpdatedTime</code>
      </td>
      <td style="text-align:left"><code>Time</code>
      </td>
      <td style="text-align:left">The time the stack was last updated. This field will only be returned
        if the stack has been updated at least once.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>NotificationARNs</code>
      </td>
      <td style="text-align:left"><code>List</code>
      </td>
      <td style="text-align:left">SNS topic ARNs to which stack related events are published.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>Outputs</code>
      </td>
      <td style="text-align:left"><code>List</code>
      </td>
      <td style="text-align:left">A list of <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_Output.html">output</a> structures.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>RoleARN</code>
      </td>
      <td style="text-align:left"><code>String</code>
      </td>
      <td style="text-align:left">The associated IAM service role.</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>Drifts</code>
      </td>
      <td style="text-align:left"><code>List</code>
      </td>
      <td style="text-align:left">Details on the drifted resources.</td>
    </tr>
  </tbody>
</table>#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:cloudformation:ap-northeast-2:123456789012:stack/example-stack",
    "Capabilities": null,
    "ChangeSetId": null,
    "DeletionTime": null,
    "Description": "This is an example stack",
    "DisableRollback": false,
    "DriftInformation": {
        "LastCheckTimestamp": "2019-01-01T00:00:00.00Z",
        "StackDriftStatus": "IN_SYNC"
    },
    "Drifts": null,
    "EnableTerminationProtection": null,
    "Id": "arn:aws:cloudformation:ap-northeast-2:123456789012:stack/example-stack",
    "LastUpdatedTime": null,
    "Name": "example-stack",
    "NotificationARNs": [
        "arn:aws:sns:ap-northeast-2:123456789012:example-topic"
    ],
    "Outputs": null,
    "Parameters": [
        {
            "ParameterKey": "Parameter1",
            "ParameterValue": "Value1",
            "ResolvedValue": null,
            "UsePreviousValue": null
        },
        {
            "ParameterKey": "Parameter2",
            "ParameterValue": "Value2",
            "ResolvedValue": null,
            "UsePreviousValue": null
        }
    ],
    "ParentId": null,
    "Region": "ap-northeast-2",
    "ResourceId": "arn:aws:cloudformation:ap-northeast-2:123456789012:stack/example-stack",
    "ResourceType": "AWS.CloudFormation.Stack",
    "RoleARN": null,
    "RollbackConfiguration": {
        "MonitoringTimeInMinutes": null,
        "RollbackTriggers": null
    },
    "RootId": null,
    "StackId": "arn:aws:cloudformation:ap-northeast-2:123456789012:stack/example-stack",
    "StackStatus": "CREATE_COMPLETE",
    "StackStatusReason": null,
    "Tags": null,
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "TimeoutInMinutes": null
}
```
