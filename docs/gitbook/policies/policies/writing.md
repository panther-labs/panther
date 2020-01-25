---
description: How to write and test policies
---

# Writing

## Policy Structure

Policies determine if cloud resources are vulnerable based on scanned metadata.

### Metadata

The following table lists metadata that you can use:

| Field Name     | Description                                                                        |
| :------------- | :--------------------------------------------------------------------------------- |
| `Description`  | Additional context on the policy                                                   |
| `DisplayName`  | A human readable name for the policy                                               |
| `PolicyID`     | A unique identifier for a policy, generally in the form of `Env.Service.Component` |
| `Reference`    | A URL explaining more details on the configuration, often site documentation       |
| `ResourceType` | The type of resource\(s\) to analyze with the policy                               |
| `Runbook`      | A URL to detailed instructions on how to fix the issue                             |
| `Severity`     | The potential impact of a misconfiguration                                         |
| `Suppressions` | Resource Id patterns to ignore in the policy                                       |
| `Tags`         | One or more categorizations of a policy                                            |

### Severity Levels

The following table describes each of the severity levels with an example:

| Severity   | Exploitability | Description                        | Examples                                                                                                                           |
| :--------- | :------------- | :--------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------- |
| `Info`     | `None`         | No risk, simply informational      | Name formatting, missing tags. General best practices for ops.                                                                     |
| `Low`      | `Difficult`    | Little to no risk if exploited     | Non sensitive information leaking such as system time and OS versions.                                                             |
| `Medium`   | `Difficult`    | Moderate risk if exploited         | Expired credentials, missing protection against accidental data loss, encryption settings, best practice settings for audit tools. |
| `High`     | `Moderate`     | Very damaging if exploited         | Large gaps in visibility, directly vulnerable infrastructure, misconfigurations directly related to data exposure.                 |
| `Critical` | `Easy`         | Causes extreme damage if exploited | Public data or systems, leaked access keys.                                                                                        |

There are two ways to write Policies, in the provided Panther UI and locally with your normal developer workflow. The sections below detail how each work.

## Panther UI

To add a new Policy in the Panther UI, click the `Create New` button on the **List Policies** page:

![Policy Editor](../../.gitbook/assets/screen-shot-2019-09-10-at-5.49.49-pm.png)

{% hint style="warning" %}
Saving policies immediately triggers analysis on all current resources, which can potentially trigger new alerts and auto-remediations.

Make sure to test the policy before saving it. If you want to save an in progress policy for future editing, set `Enabled` to `OFF` so that it will not run against your resources on save.
{% endhint %}

## Local Development

When writing policies locally, you must construct two files: The Python function body, and a JSON or YAML specification file. The body contains logic to determine vulnerable resources, and the specification file contains policy metadata and configuration settings.

### **Policy Body**

Similar to the web UI, the policy body only has only three requirements:

1. The policy body must be valid python3 code
2. The policy body must define a `policy` function that accepts one argument
3. The `policy` function must return a `bool` type

Other than that, the policy body can contain anything you find useful to writing your policies. Helper functions, global variables, comments, etc. are all permitted. By convention, we name the argument to the `policy` function `resource`, so a minimal \(and useless\) policy body would be such:

```python
def policy(resource):
    return True
```

The argument `resource` will be a map, with keys of type `str`. For definitions of these maps, see the [Resources](../resources/) documentation.

### **Specification File**

The policy specification file must be valid JSON or YAML, with a `.json` or `.yml` / `.yaml` file extension as appropriate. The accepted fields for the policy specification file are detailed below.

| Field Name                  | Required | Description                                                                                           | Expected Value                                                        |
| :-------------------------- | :------- | :---------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------- |
| `AnalysisType`              | Yes      | Indicates whether this specification is defining a policy or a rule                                   | The string `policy` or the string `rule`                              |
| `Enabled`                   | Yes      | Whether this policy is enabled                                                                        | Boolean                                                               |
| `FileName`                  | Yes      | The name \(with file extension\) of the python policy body                                            | String                                                                |
| `PolicyID`                  | Yes      | The unique identifier of the policy                                                                   | String                                                                |
| `ResourceTypes`             | Yes      | What resource types this policy will apply to                                                         | List of strings                                                       |
| `Severity`                  | Yes      | What severity this policy is                                                                          | One of the following strings: `Info | Low | Medium | High | Critical` |
| `ActionDelaySeconds`        | No       | How long \(in seconds\) to delay auto-remediations and alerts, if configured                          | Integer                                                               |
| `AlertFormat`               | No       | Not used at this time                                                                                 | NA                                                                    |
| `AutoRemediationID`         | No       | The unique identifier of the auto-remediation to execute in case of policy failure                    | String                                                                |
| `AutoRemediationParameters` | No       | What parameters to pass to the auto-remediation, if one is configured                                 | Map                                                                   |
| `Description`               | No       | A brief description of the policy                                                                     | String                                                                |
| `DisplayName`               | No       | What name to display in the UI and alerts. The `PolicyID` will be displayed if this field is not set. | String                                                                |
| `Reference`                 | No       | The reason this policy exists, often a link to documentation                                          | String                                                                |
| `Runbook`                   | No       | The actions to be carried out if this policy fails, often a link to documentation                     | String                                                                |
| `Tags`                      | No       | Tags used to categorize this policy                                                                   | List of strings                                                       |
| `Tests`                     | No       | Unit tests for this policy. See [Testing](testing.md) for details on how unit tests are formatted.    | List of maps                                                          |
