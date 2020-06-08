# Panther Analysis Tool

## Installation

The `panther_analysis_tool` is available on pip and can be installed with the following command:

```bash
pip3 install panther-analysis-tool
```

## File Organization

It's best practice to create an internal fork of Panther's open source analysis repository. To get started, navigate your local checked out copy of your custom detections.

We recommend grouping rules based on log type, such as `suricata` or `aws_cloudtrail`. Use the open source [Panther Analysis](https://github.com/panther-labs/panther-analysis) packs as a reference.

Each rule consists of a Python file (`<my-rule>.py`) containing your detection logic and a YAML/JSON specification (`<my-rule>.yml`) with the rule's attributes.

## Rule Body

Write your rule as you would above, and save it as `folder/my_new_rule.py`.

## Rule Attributes

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

## Unit Tests

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

## Running Tests

```bash
panther_analysis_tool test --path <path-to-python-code>
```

Filtering based on rule attributes:

```bash
panther_analysis_tool test --path <path-to-python-code> --filter RuleID=Category.Behavior.MoreInfo
```

## Uploading to Panther

Make sure to configure your environment with valid AWS credentials prior to running the command below. By default, this command will upload based on the exported value of `AWS_REGION`.

```bash
panther_analysis_tool upload --path <path-to-your-rules> --out tmp
```

{% hint style="info" %}
Rules with the same ID are overwritten. Locally deleted rules will not automatically delete in the rule database and must be removed manually.
{% endhint %}
