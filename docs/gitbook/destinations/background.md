# Background

Destinations are used to send alerts of policy and rule failure to the appropriate place. Whenever a policy starts failing on a resource, or a rule triggers on an event, an alert is generated and sent to the configured Destinations.

Alerts are routed based on a policy or rule's severity. When a Policy or Rule with a `Critical` severity sends an alert, it will send it to all Destinations configured to handle `Critical` alerts. In this way, one failure may kick off multiple work flows as desired, potentially creating a JIRA ticket, sending an email, and paging the on call personnel all at once.

For example, Destinations may be configured for both email and PagerDuty. Further, the email Destination may be configured to handle `Medium` , `High`, and `Critical` severity alerts while the PagerDuty Destination is configured to handle just `Critical` severity alerts. Whenever a `Medium` or `High` severity policy or rule fails, an email is sent to the configured email address. However, when a `Critical` severity policy or rule fails an email is sent to the configured email address and a page is sent to the PagerDuty integration.

Supported Destinations:

- Email
- [Slack](https://slack.com/)
- [PagerDuty](https://www.pagerduty.com/)
- Github
- JIRA
- SNS
- SQS
- OpsGenie
- Microsoft Teams

{% hint style="warning" %}
At this time, the email Destination is not supported for CloudPrem deployments. The email Destination requires additional setup, including [moving out of the SES sandbox](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/request-production-access.html), in order to function properly. This Destination \(with supporting configuration documentation\) will be available for CloudPrem customers soon.
{% endhint %}
