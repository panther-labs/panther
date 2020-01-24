# AWS Create GuardDuty Detector

#### Remediation Id

`AWS.GuardDuty.CreateDetector`

#### Description

Remediation that creates a GuardDuty detector if one doesn't exist.

#### Resource Parameters

| Name        | Description        |
| :---------- | :----------------- |
| `AccountId` | The AWS Account Id |
| `Region`    | The AWS region     |

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
      <td style="text-align:left"><code>FindingPublishingFrequency</code>
      </td>
      <td style="text-align:left">
        <p>A enum value that specifies how frequently finding updates will be published.</p>
        <p></p>
        <p>Possible values:</p>
        <ul>
          <li>FIFTEEN_MINUTES</li>
          <li>ONE_HOUR</li>
          <li>SIX_HOURS</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>#### References

- [https://docs.aws.amazon.com/cli/latest/reference/guardduty/create-detector.html](https://docs.aws.amazon.com/cli/latest/reference/guardduty/create-detector.html)
- [https://aws.amazon.com/guardduty/](https://aws.amazon.com/guardduty/)
