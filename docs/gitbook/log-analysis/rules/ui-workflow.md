# Writing Rules in the Panther UI

This page details the steps to writing Panther rules with the built-in UI. For a background on how rules work, read the [guide here](log-analysis/rules).

Navigate to `Log Analysis` > `Rules`, and click `Create New` in the top right corner.

You have the option of creating a single new rule, or bulk uploading a zip file containing rules created with the [panther_analysis_tool](panther-analysis-tool.md):

![](../../.gitbook/assets/write-rules-ui-1.png)

Select `Single` to create a new rule.

## Set Attributes

Set all the necessary rule attributes, such as the ID, Log Types, Deduplication Period, and Severity:

![](../../.gitbook/assets/write-rules-ui-2.png)

## Write Rule Function

Then write your rule function with the `rule()`, `title()`, and `dedup()` functions.

![](../../.gitbook/assets/write-rules-ui-3.png)

## Configure Tests

Finally, configure test cases to ensure your rule works as expected:

![](../../.gitbook/assets/write-rules-ui-4.png)

And click `Create` to save the rule.

Now, when any `NGINX.Access` logs are sent to Panther, this rule will automatically analyze and alert upon admin panel activity.
