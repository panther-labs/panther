# Policies

A Policy contains:

- Metadata to provide the analyst context
- An association with a specific [Resource Type](resources/)
- A `policy` function with a `resource` argument to analyze resource attributes
- Returning `True` if the resource is compliant or `False` if non-compliant

Python provides high flexibility in defining your Policy logic, and the following libraries are supported:

| Package          | Version   | Description                 | License   |
| :--------------- | :-------- | :-------------------------- | :-------- |
| `boto3`          | `1.10.46` | AWS SDK for Python          | Apache v2 |
| `policyuniverse` | `1.3.2.1` | Parse AWS ARNs and Policies | Apache v2 |
| `requests`       | `2.22.0`  | Easy HTTP Requests          | Apache v2 |

By default, Policies are loaded from Panther's [open-source packs](https://github.com/panther-labs/panther-analysis/tree/master/analysis/policies) which cover the CIS Benchmark. You can easily write your own policies based on specific internal use cases.

Each page in this section describes helpful context for the AWS policies included with Panther by default. They include guidance on how to remediate policy failures along with recommended steps and security best practices.

## Listing Policies

To view all Policies in the Panther UI, click `Cloud Security` > `Policies` button on the sidebar.

Policies can be filtered and sorted based on:
- Name
- Resource Type
- Severity
- Status
- Tags
- Auto Remediation Status

![](../../.gitbook/assets/screen-shot-2019-09-10-at-5.44.52-pm.png)

## Viewing Failing Policies

Initially, a Policy's `status` will be set to `Insufficient data` until an event matching the given resource type is analyzed. Once it's analyzed, alerts will dispatch per the policies severity and then can be searched.

To display an overview of all `Failing` Policies, click `Cloud Security` > `Overview`.
