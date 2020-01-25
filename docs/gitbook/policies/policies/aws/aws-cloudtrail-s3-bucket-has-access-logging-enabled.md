# AWS CloudTrail S3 Bucket Has Access Logging Enabled

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Low**            |

This policy validates that CloudTrail Logs are logging to an S3 bucket where access logging is configured.

Access logs provide an audit trail of all activity to the bucket, and can be used to verify no unauthorized activity has occurred. CloudTrail logs include detailed events of what happens in your AWS environment, and it is a security best practice to monitor who is accessing, modifying, or deleting these logs.

**Remediation**

To remediate this, enable S3 bucket access logging for the S3 bucket that is failing on this rule.

| Using the AWS Console                                                                                   |
| :------------------------------------------------------------------------------------------------------ |
| 1. Navigate to the [S3 Console](https://s3.console.aws.amazon.com/s3/home#).                            |
| 2. Select the name of the S3 bucket for the relevant CloudTrail to enable S3 bucket access logging.     |
| 3. Select the "Properties" tab.                                                                         |
| 4. Select "Server access logging".                                                                      |
| 5. Select the "Enable logging" radio button.                                                            |
| 6. Choose a destination S3 bucket to log to and a prefix \(if desired\), then select the "Save" button. |

| Using the AWS CLI                                                                                                                                                                                                                                                                                                |
| :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. First, permissions must be set on the target S3 bucket to allow the CloudTrail S3 bucket to write its access logs to it. Run the following command:                                                                                                                                                           |
| `aws s3api put-bucket-acl --bucket <target_bucket_name> --grant-write URI=`[`http://acs.amazonaws.com/groups/s3/LogDelivery`](http://acs.amazonaws.com/groups/s3/LogDelivery) `--grant-read-acp URI=`[`http://acs.amazonaws.com/groups/s3/LogDelivery`](http://acs.amazonaws.com/groups/s3/LogDelivery)          |
| 2. You must create a logging policy document to put on the S3 bucket. This document dictates where to log, and who can view the logs. Create this document and save it somewhere to be referred to in the next step. See below for an example, which could be stored in a file at for example /tmp/logging.json. |
| 3. Put the newly created logging policy onto the bucket. Run the following command replacing `<path_to_policy>` with the path to the logging policy created in step 2:                                                                                                                                           |
| `aws s3api put-bucket-logging --bucket <cloudtrail_bucket_name> --bucket-logging-status file://<path_to_policy>`                                                                                                                                                                                                 |

Example logging policy. This is just one example, grantees can be of several forms. See the [AWS user documentation](https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html) for further details.

```javascript
{
  "LoggingEnabled": {
    "TargetBucket": "<target_bucket>",
    "TargetPrefix": "<optional_prefix>/",
    "TargetGrants": [
      {
        "Grantee": {
          "DisplayName": "<user_name>",
          "ID": "<user_id>",
          "Type": "CanonicalUser"
        },
        "Permission": "FULL_CONTROL"
      }
    ]
  }
}
```

**References**

- CIS AWS Benchmark 2.6 "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"
