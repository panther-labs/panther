# SaaS Logs

Panther Enterprise supports pulling logs directly from SaaS platforms such as Okta, OneLogin, and more.

The two mechanisms used are direct integrations (by querying APIs) and AWS EventBridge.

## Direct

Supported direct SaaS integrations include:
* [Okta](okta.md)
* [G Suite](gsuite.md)
* [Box](box.md)
* More coming soon!

To set up, head to `Log Analysis` > `Sources` > `Add Source`, and select one of the integrations listed.

{% hint style="info" %}
By default, we poll for new logs every minute.
{% endhint %}

## EventBridge

Panther has direct support for pulling log data from AWS EventBridge, enabling real-time streaming and simple ingestion of [support SaaS integrations](https://aws.amazon.com/eventbridge/integrations/).

* [OneLogin](onelogin.md)
* *(Coming soon!)* Auth0
* *(Coming soon!)* NewRelic
* *(Coming soon!)* ZenDesk

To set up, head to `Log Analysis` > `Sources` > `Add Source` and select `Amazon EventBridge`:

![EventBridge](../.gitbook/assets/enterprise/saas-logs/eventbridge.png)
