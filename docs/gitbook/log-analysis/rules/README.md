# Rules

### What is a Rule?

A Rule includes:

- Metadata to provide context to the analyst
- An association with a specific Log Type
- A `rule` function with an `event` argument to analyze the log
- Returning `True` if the rule should trigger an alert, `False` otherwise

Python provides high flexibility in defining your Rule logic, and the following libraries are supported:

| Package          | Version   | Description                 | License   |
| :--------------- | :-------- | :-------------------------- | :-------- |
| `boto3`          | `1.10.46` | AWS SDK for Python          | Apache v2 |
| `policyuniverse` | `1.3.2.1` | Parse AWS ARNs and Policies | Apache v2 |
| `requests`       | `2.22.0`  | Easy HTTP Requests          | Apache v2 |

By default, Policies are loaded from Panther's [open-source packs](https://github.com/panther-labs/panther-analysis/tree/master/analysis/policies) which cover the CIS Benchmark.

### Supported Log Types

The following log types are currently supported:

#### [AWS](https://github.com/panther-labs/panther/tree/master/internal/log_analysis/log_processor/parsers/awslogs)

- Application Load Balancer
- Aurora MYSQL Audit
- CloudTrail
- GuardDuty
- S3 Server Access
- VPC Flow

#### [osquery](https://github.com/panther-labs/panther/tree/master/internal/log_analysis/log_processor/parsers/osquerylogs)

- Batch
- Differential
- Snapshot
- Status

### Built-in Rules

{% hint style="info" %}
Coming soon
{% endhint %}
