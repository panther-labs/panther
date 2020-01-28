# Background

Destinations are used to send alerts about suspicious activity or vulnerable infrastructure.

Whenever a policy fails on a resource or a rule triggers on an event, an alert is generated and sent to the configured Destination.

Alerts are routed based on rule/policy severity. For example, if Rule is configured with a `Critical`, it will dispatch alerts to the default Destinations configured to handle `Critical` alerts.

{% hint style="info" %}
A single failure may dispatch to multiple destinations simultaneously, such as creating a JIRA ticket, sending an email, or paging the on call personnel.
{% endhint %}

For example, Destinations may be configured for both email and PagerDuty. Further, the email Destination may be configured to handle `Medium` , `High`, and `Critical` severity alerts while the PagerDuty Destination is configured to handle just `Critical` severity alerts. Whenever a `Medium` or `High` severity policy or rule fails, an email is sent to the configured email address. However, when a `Critical` severity policy or rule fails an email is sent to the configured email address and a page is sent to the PagerDuty integration.

Supported Destinations:

- [Slack](https://slack.com/)
- [PagerDuty](https://www.pagerduty.com/)
- Github
- JIRA
- SNS (Email)
- SQS
- OpsGenie
- Microsoft Teams
