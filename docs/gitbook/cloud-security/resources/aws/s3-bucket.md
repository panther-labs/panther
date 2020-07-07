---
description: Simple Storage Service (S3) Bucket
---

# S3 Bucket

#### Resource Type

`AWS.S3.Bucket`

#### Resource ID Format

For S3 Buckets, the resource ID is the ARN.

`arn:aws:s3:::example-bucket`

#### Background

S3 is an object storage service offered by AWS for organization of data.

#### Fields

| Field                            | Type     | Description                                                                                                                                                                                         |
| :------------------------------- | :------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Grants`                         | `List`   | What users, groups, or roles have been granted access to this S3 bucket and what access they have been granted.                                                                                     |
| `LifecycleRules`                 | `List`   | [Rules](https://docs.aws.amazon.com/AmazonS3/latest/API/API_LifecycleRule.html) for managing the expiration and archival of data.                                                                   |
| `EncryptionRules`                | `List`   | [Rules](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ServerSideEncryptionRule.html) for encrypting the S3 bucket.                                                                            |
| `LoggingPolicy`                  | `Map`    | [Describes](https://docs.aws.amazon.com/AmazonS3/latest/API/API_LoggingEnabled.html) where access logs are stored.                                                                                  |
| `MFADelete`                      | `String` | Indicates if MFA delete is Enabled on the bucket or not. If not, this value will be blank.                                                                                                          |
| `ObjectLockConfiguration`        | `Map`    | These [configuration options](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ObjectLockConfiguration.html) prevent an object from being deleted or overwritten for a specified amount of time. |
| `Owner`                          | `Map`    | [Information](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Owner.html) on the Bucket owner.                                                                                                  |
| `Policy`                         | `String` | The IAM policy attached to the bucket.                                                                                                                                                              |
| `Versioning`                     | `String` | `ENABLED | SUSPENDED`                                                                                                                                                                               |
| `PublicAccessBlockConfiguration` | `Map`    | Indicates how the S3 bucket's [Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html) settings are configured.                               |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:s3:::example-bucket",
    "EncryptionRules": [
        {
            "ApplyServerSideEncryptionByDefault": {
                "KMSMasterKeyID": "1",
                "SSEAlgorithm": "aws:kms"
            }
        }
    ],
    "Grants": [
        {
            "Grantee": {
                "DisplayName": "example.user",
                "EmailAddress": null,
                "ID": "1",
                "Type": "CanonicalUser",
                "URI": null
            },
            "Permission": "FULL_CONTROL"
        }
    ],
    "LifecycleRules": [
        {
            "AbortIncompleteMultipartUpload": null,
            "Expiration": null,
            "Filter": {
                "And": null,
                "Prefix": null,
                "Tag": null
            },
            "ID": "1",
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": 365
            },
            "NoncurrentVersionTransitions": null,
            "Prefix": null,
            "Status": "Enabled",
            "Transitions": null
        }
    ],
    "LoggingPolicy": {
        "TargetBucket": "example-bucket-2",
        "TargetGrants": null,
        "TargetPrefix": "/"
    },
    "MFADelete": null,
    "Name": "example-bucket",
    "ObjectLockConfiguration": null,
    "Owner": {
        "DisplayName": "example.user",
        "ID": "1"
    },
    "Policy": null,
    "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": true,
        "BlockPublicPolicy": true,
        "IgnorePublicAcls": true,
        "RestrictPublicBuckets": true
    },
    "Region": "us-west-2",
    "ResourceId": "arn:aws:s3:::example-bucket",
    "ResourceType": "AWS.S3.Bucket",
    "Tags": {
        "Key1": "Value1",
        "Key2": "Value2"
    },
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "Versioning": "Enabled"
}
```
