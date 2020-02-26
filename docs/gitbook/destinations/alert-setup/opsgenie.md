# OpsGenie

This page will walk you through configuring OpsGenie as a Destination for your Panther alerts.

The OpsGenie Destination requires an `Opsgenie API key`. When an alert is forwarded to an OpsGenie Destination, it creates an incident using the specified API key:

![](../../.gitbook/assets/screen-shot-2019-10-22-at-10.34.10-am.png)

1. To configure an OpsGenie Destination, start by navigating to your team's dashboard by going to the Teams tab and selecting the team to receive the alert:

![](../../.gitbook/assets/screen-shot-2019-10-23-at-9.28.46-am.png)

2. After selecting the team you to which you wish to send alerts, select the integrations tab on the left:

![](../../.gitbook/assets/screen-shot-2019-10-23-at-9.31.08-am%20%281%29.png)

3. Select the `Add integration` button:

![](../../.gitbook/assets/screen-shot-2019-10-23-at-9.35.22-am.png)

4. Next select the `API` integration type from the integration list:

![](../../.gitbook/assets/screen-shot-2019-10-23-at-9.35.41-am.png)

5. After selecting the API integration type, you will be prompted to configure the name, settings, permissions, etc. of the integration. Be sure to leave the `Enabled` and `Create and Update Access` check boxes checked:

![](../../.gitbook/assets/screen-shot-2019-10-23-at-9.44.49-am.png)

6. Copy the API key out of the configuration settings and into the Panther Destinations configuration, and select the `Save Integration` button. Your OpsGenie Destination should now be ready to receive alerts from Panther
