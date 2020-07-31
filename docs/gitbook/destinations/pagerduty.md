# PagerDuty

[PagerDuty](https://www.pagerduty.com/) is a service to manage on-call rotations for critical systems.

To configure a PagerDuty Destination, Panther requires an `Integration Key`. When an alert is forwarded to a PagerDuty Destination, it creates an incident:

![](../.gitbook/assets/destinations/pagerduty-panther.png)

The PagerDuty Destination allows you to page an on-call team. We typically only recommend this Destination for `High` and `Critical` severity issues that need to be addressed immediately.

To configure the PagerDuty Destination, go to the PagerDuty Service Directory configuration page `(https://<your-domain>.pagerduty.com/service-directory)` and select the `New Service` button:

![](../.gitbook/assets/destinations/pagerduty1.png)

You will be presented with a service configuration page. Select the `Use our API directly` option for the Integration Type, then configure the service with a name, description, escalation policy, and any other settings as you see fit:

![](../.gitbook/assets/destinations/pagerduty2.png)

After the service has been created, you will be redirected to the Integrations page for that service from which you can copy out the integration key for the Panther Destinations configuration:

![](../.gitbook/assets/destinations/pagerduty3.png)

{% hint style="success" %}
The PagerDuty configuration is now set and ready to receive alerts from Panther!
{% endhint %}
