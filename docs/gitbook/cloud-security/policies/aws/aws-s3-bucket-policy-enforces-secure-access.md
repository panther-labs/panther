# AWS S3 Bucket Policy Enforces Secure Access

| Risk    | Remediation Effort |
| :------ | :----------------- |
| **Low** | **Low**            |

This policy validates that all S3 Buckets enforce secure \(HTTPS\) access. This enforces encryption in transit of all information read from the bucket.

**Remediation**

To remediate this, add the following condition to the S3 Bucket Access Policy:

{% tabs %}
{% tab title="policy.json" %}

```javascript
{
    "Version": "2012-10-17",
    "Id": "Policy1504640911349",
    "Statement": [
        {
            "Sid": "Stmt1504640908907",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::/*",
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
```

{% endtab %}

{% tab title="policy.yml" %}

```
Version: 2012-10-17
Id: Policy1504640911349
Statement:
  -
    Sid: Stmt1504640908907
    Effect: Deny
    Principal: '*'
    Action: s3:GetObject
    Resource: arn:aws:s3:::/*
    Condition:
      Bool:
        aws:SecureTransport: 'false'
```

{% endtab %}
{% endtabs %}

**Reference**

- AWS S3 Bucket [defense in depth](https://aws.amazon.com/blogs/security/how-to-use-bucket-policies-and-apply-defense-in-depth-to-help-secure-your-amazon-s3-data/) guide
