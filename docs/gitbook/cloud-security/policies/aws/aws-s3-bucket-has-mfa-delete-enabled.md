# AWS S3 Bucket Has MFA Delete Enabled

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that a S3 bucket has MFA Delete enabled.

MFA delete ensures that all actions to delete objects in the bucket are authenticated with MFA. This provides an additional layer of security against malicious or accidental data loss.

**Remediation**

To remediate this, you must use a root account access key and execute the following command:

```text
$ aws put-bucket-versioning --bucket <example-bucket> MFADelete=Enabled
```

{% hint style="info" %}
This cannot be performed from the AWS Console or in CloudFormation
{% endhint %}

**Reference**

- AWS S3 Bucket [MFA Delete](https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete) documentation
