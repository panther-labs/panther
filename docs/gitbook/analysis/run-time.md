# Runtime Libraries

The following Python libraries are available to be used in Panther in addition to `boto3` provided by [AWS Lambda](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html):

| Package          | Version   | Description                 | License   |
| :--------------- | :-------- | :-------------------------- | :-------- |
| `policyuniverse` | `1.3.2.2` | Parse AWS ARNs and Policies | Apache v2 |
| `requests`       | `2.23.0`  | Easy HTTP Requests          | Apache v2 |

To add more libraries, edit the `PipLayer` below in the `panther_config.yml`:

```yaml
PipLayer:
  - policyuniverse==1.3.2.2
  - requests==2.23.0
```

Alternatively, you can override the runtime libraries by attaching a custom Lambda layer in the `panther_config.yml`:

```yaml
BackendParameterValues:
  PythonLayerVersionArn: 'arn:aws:lambda:us-east-2:123456789012:layer:my-layer:3'
```

{% hint style="info" %}
For Panther Cloud customers, file a support ticket to have a custom layer or set of libraries applied
{% endhint %}
