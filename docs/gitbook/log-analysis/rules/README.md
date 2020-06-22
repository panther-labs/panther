# Rules

Panther **Rules** are Python3 functions used to identify suspicious activity and generate helpful signal for your team.

## Rule Components

- A `rule` function with an `event` argument that returns `True` if the rule should send an alert, or `False` if it should not
- A `dedup` function to control how alerts are grouped together
- A `title` function to define the alert title
- Metadata containing context for triage
- An association with specific log type(s)

The example rule below validates if unauthenticated access occurred on an S3 bucket:

```python
def rule(event):
  if event.get('bucket') not in {'my-super-secret-data'}:
    return False
  return 'requester' not in event

def dedup(event):
  return event.get('bucket')

def title(event):
  return 'Unauthenticated Access to S3 Bucket  {}'.format(event.get('bucket'))
```

- This rule applies to the [S3 Server Access Logs](log-analysis/log-processing/supported-logs/aws#aws-s-3-serveraccess) schema
- This rule group alerts by the bucket name
- Alerts will have a title such as `Unauthenticated Access to S3 Bucket my-super-secret-data`

## Workflow

Panther rules can be written, tested, and deployed either with the UI or the [panther_analysis_tool](panther-cli.md).

Each rule takes an `event` input of a given log type from the [supported logs](https://docs.runpanther.io/supported-logs) page.

### Rule Body

The rule body MUST:
* Be valid Python3
* Define a `rule()` function that accepts one argument (generally called `event`)
* Return `True or False` from the rule function

```python
def rule(event):
  return False
```

The rule body SHOULD:
* Name the argument to the `rule()` function `event`

The Python body MAY:
* Import standard Python3 libraries
* Import from the user defined globals
* Define additional helper functions as needed
* Define variables and classes outside the scope of the rule function
* Define a `dedup(event)` function that returns a `string`
* Define a `title(event)` function that returns a `string`

Referencing the [supported logs](https://docs.runpanther.io/supported-logs) page provides details on all available fields in events.

When accessing event fields, it's recommended to always use `.get()` since empty key/values are omitted from the event.

#### Example Rule

Let's write a rule on an [NGINX Access](../log-processing/supported-logs/Nginx.md) log:

```json
{
  "bodyBytesSent": 193,
  "httpReferer": "https://domain1.com/?p=1",
  "httpUserAgent": "Chrome/80.0.3987.132 Safari/537.36",
  "remoteAddr": "180.76.15.143",
  "request": "GET /admin-panel/ HTTP/1.1",
  "status": 200,
  "time": "2019-02-06 00:00:38 +0000 UTC"
}
```

This example rule alerts on successful admin panel logins:

```python
def rule(event):
  return 'admin-panel' in event.get('request') and event.get('status') == 200
```

In the `rule()` body, returning a value of `True` indicates an alert should send. Returning a value of `False` indicates the log is not suspicious.

### Alert Deduplication

To avoid a flood of alerts, events are grouped together within a given time period and associated with a single `alertID`.

By default, events are merged by the key `defaultDedupString:${RuleID}` over a period of `1h`.

Each of these options are fully configurable.

{% hint style="warn" %}
The deduplication string is limited to `1000` characters and will be truncated if it goes over.
{% endhint %}

To modify the deduplication key, use the `dedup()` function in your rule body.

The same parsed log `event` is passed into this function, and you may use any logic desired to return the `dedupString`. If a Falsy value is returned from `dedup()`, then the default string will be used.

The `dedupPeriodMinutes` may be set to either `15m`, `30m`, `1h`, `3h`, `12h`, or `24h`.

To keep with the previous example, all events will merge on the requested webpage:

```python
def dedup(event):
  return event.get('request', '').split(' ')[1]
```

### Alert Titles

Alert titles, sent to our destinations, are by default `New Alert: ${Rule Description}`. To override this message, use the `title()` function:

```python
def title(event):
  return 'successful /admin-panel/ logins'
```

The title can also be interpolated by using event attributes:

```python
def title(event):
  return 'successful logins to {}'.format(event.get('request').split(' ')[1])
```

## First Steps with Rules

When starting your rule writing/editing journey, your team should decide between a UI or CLI driven workflow.

Then, configure the built in rules by searching for the `Configuration Required` tag. These rules are designed to be modified by you, the security professional, based on your organization's business logic.

## Writing Rules in the Panther UI

Navigate to Log Analysis > Rules, and click `Create New` in the top right corner. You have the option of creating a single new rule, or uploading a zip file containing rules created with the [panther_analysis_tool](panther-cli.md).

![](../../.gitbook/assets/write-rules-ui-1.png)

### Set Attributes

Keeping with the NGINX example above, set all the necessary rule attributes:

![](../../.gitbook/assets/write-rules-ui-2.png)

### Write Rule Body

Then write your rule function with the `rule()`, `title()`, and `dedup()` functions.

![](../../.gitbook/assets/write-rules-ui-3.png)

### Configure Tests

Finally, configure test cases to ensure your rule works as expected:

![](../../.gitbook/assets/write-rules-ui-4.png)

And click `Create` to save the rule.

Now, when any `NGINX.Access` logs are sent to Panther this rule will automatically analyze and alert upon admin panel activity.

## Writing Rules with the Panther Analysis Tool

The [panther_analysis_tool](panther-cli.md) is a Python command line interface  for testing, packaging, and deploying Panther Policies and Rules. This enables teams to work in a more developer oriented workflow and track detections with version control systems such as `git`.
