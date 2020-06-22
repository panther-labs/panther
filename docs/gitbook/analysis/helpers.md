## Reusable Code

Often, you may find yourself repeating the same logic over and over again when writing policies. A common pattern in programming is to extract this repeated code out into helper functions, which is supported in Panther with the `global` analysis type.

To make use of this `global`, simply add `import panther` to your policy code and then you can use the helper functions defined there as if it were any other python library. For example:

```python
import panther

def policy(resource):
    bucket_name = panther.get_s3_arn_by_name(resource['bucket'])
    bucket = panther.resource_lookup(bucket_name)
    return bucket['EncryptionRules'] is not None
```

This policy first makes use of a function named `get_s3_arn_by_name` to convert an s3 bucket name into an s3 bucket ARN.

Secondly, this policy makes uses the `resource_lookup` helper to fetch a related resource on its ARN. This allows the contents of one resource to be used in the evaluation of another resource.

These functions (and more) are deployed as part of the out-of-the-box `global` modules.
