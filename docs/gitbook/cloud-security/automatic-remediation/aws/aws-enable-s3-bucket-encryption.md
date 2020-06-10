# AWS Enable S3 Bucket Encryption

#### Remediation Id

`AWS.S3.EnableBucketEncryption`

#### Description

Remediation that enables default encryption for an S3 bucket.

#### Resource Parameters

| Name        | Description                      |
| :---------- | :------------------------------- |
| `AccountId` | The AWS Account Id of the bucket |
| `Region`    | The AWS region of the bucket     |
| `Name`      | The name of the S3 bucket        |

#### Additional Parameters

| Name             | Description                                                                         |
| :--------------- | :---------------------------------------------------------------------------------- |
| `SSEAlgorithm`   | The SSE Encryption algorithm to use. Can be `AES256` or `aws:kms`                   |
| `KMSMasterKeyID` | The ID of the KMS Key to use. Needs to be set only if the SSEAlgorithm is `aws:kms` |

#### References

- [https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html](https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html)
