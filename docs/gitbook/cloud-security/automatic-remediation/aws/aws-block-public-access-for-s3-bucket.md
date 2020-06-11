# AWS Block Public Access for S3 Bucket

#### Remediation Id

`AWS.S3.BlockBucketPublicAccess`

#### Description

Remediation that modifies the S3 bucket block public access configuration.

#### Resource Parameters

| Name        | Description                      |
| :---------- | :------------------------------- |
| `AccountId` | The AWS Account Id of the bucket |
| `Region`    | The AWS region of the bucket     |
| `Name`      | The name of the S3 bucket        |

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
      <td style="text-align:left"><code>BlockPublicAcls</code>
      </td>
      <td style="text-align:left">
        <p>Boolean that specifies whether Amazon S3 should block public access control
          lists (ACLs) for this bucket. Setting this element to <code>true</code> causes
          the following behavior:</p>
        <ul>
          <li>PUT Bucket ACL and PUT Object ACL calls fail if the specified ACL is public.</li>
          <li>PUT Object calls fail if the request includes a public ACL.</li>
        </ul>
        <p>Enabling this setting doesn&apos;t affect existing policies or ACLs</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><code>IgnorePublicAcls</code>
      </td>
      <td style="text-align:left">Boolean that specifies whether Amazon S3 should ignore public ACLs for
        this bucket. Enabling this setting doesn&apos;t affect the persistence
        of any existing ACLs and doesn&apos;t prevent new public ACLs from being
        set</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>BlockPublicPolicy</code>
      </td>
      <td style="text-align:left">Boolean that specifies whether Amazon S3 should block public bucket policies
        for this bucket. If set to <code>true,</code>Amazon S3 will reject calls
        to PUT Bucket policy if the specified policy allows public access</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>RestrictPublicBuckets</code>
      </td>
      <td style="text-align:left">
        <p>Boolean that specifies whether Amazon S3 should restrict public bucket
          policies for this bucket. If set to <code>true</code>, only AWS services
          and authorized users within the bucket owner&apos;s account can access
          this bucket if it has a public bucket policy.</p>
        <p>Enabling this setting doesn&apos;t affect previously stored bucket policies,
          except that public and cross-account access within any public bucket policy,
          including non-public delegation to specific accounts, is blocked.</p>
      </td>
    </tr>
  </tbody>
</table>#### References

- [https://docs.aws.amazon.com/cli/latest/reference/s3api/put-public-access-block.html](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-public-access-block.html)
- [https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html](https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html)
