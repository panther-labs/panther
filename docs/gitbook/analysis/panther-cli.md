# Panther Analysis Tool

The `panther_analysis_tool` is an [open source](https://github.com/panther-labs/panther_analysis_tool) Python utility for testing, packaging, and deploying Panther rules/policies to your Panther installation. It's designed to enable developer-centric workflows, such as managing your Panther analysis packs with CI/CD pipelines.

## Installation

```bash
pip3 install panther-analysis-tool
```

## File Organization

{% hint style="info" %}
It's best practice to create a fork of Panther's open source analysis repository.
{% endhint %}

To get started, navigate the locally checked out copy of your custom detections.

We recommend grouping rules based on log type, such as `suricata_rules` or `aws_cloudtrail_rules`. Use the open source [Panther Analysis](https://github.com/panther-labs/panther-analysis) packs as a reference.

Each rule consists of:

1. A Python file containing your detection/audit logic
2. A valid YAML or JSON specification file of the same filename as the Python file with metadata and attributes

## Writing Rules

[Write your rule](log-analysis/rules/README.md) and save it as `my_new_rule.py`:

```python
def rule(event):
  return 'prod' in event.get('hostName')
```

Add the specification and set the `AnalysisType` to `rule`, for example:

```yml
AnalysisType: rule
DedupPeriodMinutes: 60 # 1 hour
DisplayName: Example Rule to Check the Format of the Spec
Enabled: true
Filename: my_new_rule.py
RuleID: Type.Behavior.MoreContext
Severity: Info, Low, Medium, High, or Critical
LogTypes:
  - LogType.GoesHere
Reports:
  ReportName (like CIS, MITRE ATT&CK):
    - The specific report section relevant to this rule
Tags:
  - Tags
  - Go
  - Here
Description: >
  This rule exists to validate the CLI workflows of the Panther CLI
Runbook: >
  First, find out who wrote this the spec format, then notify them with feedback.
Reference: https://www.a-clickable-link-to-more-info.com
```

### Rule Tests

Tests can help validate that your Rules behave as intended. In your spec file, add the `Tests` key:

```yml
Tests:
  -
    Name: Name to describe our first test.
    LogType: LogType.GoesHere
    ExpectedResult: true or false
    Log:
      {
        "hostName": "test-01.prod.acme.io",
        "user": "martin_smith",
        "eventTime": "June 22 5:50:52 PM"
      }
```

{% hint style="info" %}
Try to cover as many test cases as possible, including false and true positives.
{% endhint %}

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
