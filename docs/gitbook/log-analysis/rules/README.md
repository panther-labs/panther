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

By default, Rules are loaded from Panther's [open-source packs](https://github.com/panther-labs/panther-analysis/tree/master/analysis/rules) which cover various detections across our supported logs.
