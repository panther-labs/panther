# Microsoft Teams

This page will walk you through configuring MS Teams as a Destination for your Panther alerts.

The MS Teams Destination requires a `Microsoft Teams Webhook URL`. When an alert is forwarded to an MS Teams Destination, it sends a message to the specified Webhook URL:

![](../.gitbook/assets/screen-shot-2019-10-21-at-1.00.38-pm.png)

The Microsoft Teams Destination is configured via a custom connector with a Webhook URL. First, ensure that your team has the option to add Incoming Webhooks as a connector. Go the `Apps` settings at the bottom left of you Teams client, then select `Connectors` and then `Incoming Webhook`:

![](../.gitbook/assets/screen-shot-2019-10-22-at-10.53.48-am.png)

Select the `Add to a team` button and you will be prompted to select a team to add the Incoming Webhook connector to, select the appropriate team and select `Setup a connector`:

![](../.gitbook/assets/screen-shot-2019-10-22-at-10.59.04-am.png)

Select the `Configure` button next to Incoming Webhook, and configure the name, description, and other settings as appropriate:

![](../.gitbook/assets/screen-shot-2019-10-22-at-10.59.33-am.png)

You will be prompted to name the integration, and optionally upload an image to display. After filling out these settings, select the `Create` button:

![](../.gitbook/assets/screen-shot-2019-10-23-at-5.10.19-pm.png)

You will then be presented with the webhook URL. Copy this out into the Panther Destinations page and select the `Done` button:

![](../.gitbook/assets/screen-shot-2019-10-24-at-8.20.34-am.png)

Your MS Teams destination is now ready to receive notifications when Policies and Rules send alerts:

![](../.gitbook/assets/screen-shot-2019-10-24-at-8.29.42-am.png)
