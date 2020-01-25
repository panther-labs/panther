# AWS Block S3 Bucket Public ACL

#### Remediation Id

`AWS.S3.BlockBucketPublicACL`

#### Description

Remediation that sets the S3 bucket ACL to private.

| Name        | Description                      |
| :---------- | :------------------------------- |
| `AccountId` | The AWS Account Id of the bucket |
| `Region`    | The AWS region of the bucket     |
| `Name`      | The name of the S3 bucket        |

#### References

- [https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-acl.html](https://docs.aws.amazon.com/cli/latest/reference/s3api/put-bucket-acl.html)
