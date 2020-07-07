# AWS Publish VPC Flow Logs to S3

#### Remediation Id

`AWS.EC2.EnableVpcFlowLogsToS3`

#### Description

Remediation that creates a configures VPC FlowLogs to send to S3.

#### Resource Parameters

| Name        | Description                   |
| :---------- | :---------------------------- |
| `AccountId` | The AWS Account Id of the VPC |
| `Region`    | The AWS region of the VPC     |
| `Id`        | The VPC Id                    |

#### Additional Parameters

<table>
  <thead>
    <tr>
      <th style="text-align:left">Name</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><code>TargetBucketName</code>
      </td>
      <td style="text-align:left">Specifies the name of the Amazon S3 bucket designated for publishing log
        files</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>TargetPrefix</code>
      </td>
      <td style="text-align:left">Specifies the Amazon S3 key prefix that comes after the name of the bucket
        you have designated for log file delivery</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>TrafficType</code>
      </td>
      <td style="text-align:left">
        <p>The type of traffic to log. You can log traffic that the resource accepts
          or rejects, or all traffic.</p>
        <p>Possible values:</p>
        <ul>
          <li>ACCEPT</li>
          <li>REJECT</li>
          <li>ALL</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>#### References

- [https://docs.aws.amazon.com/cli/latest/reference/ec2/create-flow-logs.html](https://docs.aws.amazon.com/cli/latest/reference/ec2/create-flow-logs.html)
- [https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3.html](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3.html)
