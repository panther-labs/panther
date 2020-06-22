# Panther Analysis Tool

The `panther_analysis_tool` is a Python command line interface  for testing, packaging, and deploying Panther Policies and Rules.

## Installation

Install the [panther_analysis_tool](https://github.com/panther-labs/panther_analysis_tool) with the following command:

```bash
pip3 install panther-analysis-tool
```

## File Organization

It's best practice to create a fork of Panther's open source analysis repository.

To get started, navigate your local checked out copy of your custom detections.

We recommend grouping rules based on log type, such as `suricata` or `aws_cloudtrail`. Use the open source [Panther Analysis](https://github.com/panther-labs/panther-analysis) packs as a reference.

Each rule consists of a Python file (`<my_analysis_file>.py`) containing your detection/audit logic and a YAML/JSON specification (`<my_analysis_file>.yml`) with the given metadata and attributes.

## Writing Rules

[Write your rule](log-analysis/rules/) and save it as `my_new_rule.py`.

The specification file MUST:

* Be valid JSON or YAML
* Define an `AnalysisType` field with the value `rule`

Define the additional following fields:
* `Enabled`
* `FileName`
* `RuleID`
* `LogTypes`
* `Severity`

An example specification file:

```yml
AnalysisType: rule
Enabled: true
Filename: my_new_rule.py
RuleID: Category.Behavior.MoreInfo
DisplayName: Example Rule to Check the Format of the Spec
DedupPeriodMinutes: 60 # 1 hour
LogTypes:
  - Log.Type.Here
Severity: Info, Low, Medium, High, or Critical
Tags:
  - Tags
  - Go
  - Here
Runbook: Find out who changed the spec format.
Reference: https://www.link-to-info.io
```

### Rule Tests

In your spec file, add the following key:

```yml
Tests:
  -
    Name: Name to describe our first test.
    LogType: Log.Type.Here
    ExpectedResult: true/false
    Log:
      Key: Values
      For: Our Log
      Based: On the Schema
```

## Writing Policies

The specification file MUST:

* Be valid JSON/YAML
* Define an `AnalysisType` field with the value `policy`

Define the additional following fields:
* `Enabled`
* `FileName`
* `PolicyID`
* `ResourceTypes`
* `Severity`

An example specification file:

```yml
AnalysisType: policy
Enabled: true
Filename: my_new_policy.py
PolicyID: Category.Type.MoreInfo
ResourceType:
  - Resource.Type.Here
Severity: Info|Low|Medium|High|Critical
DisplayName: Example Policy to Check the Format of the Spec
Tags:
  - Tags
  - Go
  - Here
Runbook: Find out who changed the spec format.
Reference: https://www.link-to-info.io
```

The complete list of accepted fields for the policy specification file are detailed below.

| Field Name                  | Required | Description                                                                                           | Expected Value                                                        |
| :-------------------------- | :------- | :---------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------- |
| `AnalysisType`              | Yes      | Indicates whether this specification is defining a policy or a rule                                   | The string `policy` or the string `rule`                              |
| `Enabled`                   | Yes      | Whether this policy is enabled                                                                        | Boolean                                                               |
| `FileName`                  | Yes      | The path \(with file extension\) to the python policy body                                            | String                                                                |
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
| `Tests`                     | No       | Unit tests for this policy.    | List of maps                                                          |

### Automatic Remediation

Automatic remediations require two fields to be configured in the spec file:
* `AutoRemediationID`: The automatic remediation to enable
* `AutoRemediationParameters`: The expected configurations for the remediation

For a complete list of remediations and their associated configurations, see the [remediations](cloud-security/automatic-remediation/aws) page.

### Policy Tests

In our spec file, add the following key:

```yml
Tests:
  -
    Name: Name to describe our first test.
    ResourceType: Resource.Type.Here
    ExpectedResult: true/false
    Resource:
      Key: Values
      For: Our Resource
      Based: On the Schema
```

## Running Tests

```bash
panther_analysis_tool test --path <path-to-your-rules>
```

Filtering based on rule attributes:

```bash
panther_analysis_tool test --path <path-to-your-rules> --filter RuleID=Category.Behavior.MoreInfo
```

## Uploading to Panther

Make sure to configure your environment with valid AWS credentials prior to running the command below. By default, this command will upload based on the exported value of `AWS_REGION`.

```bash
panther_analysis_tool upload --path <path-to-your-rules> --out tmp
```

{% hint style="warning" %}
Rules with the same ID are overwritten. Locally deleted rules will not automatically delete in the rule database and must be removed manually.
{% endhint %}

{% hint style="info" %}
For Panther Cloud customers, file a support ticket to gain upload access to your Panther environment.
{% endhint %}
