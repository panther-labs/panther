# Overview

Destinations are used to notify your team about suspicious activity or vulnerable cloud infrastructure.

When a policy fails on a resource or a rule triggers on an event, an alert is generated and sent to the configured destination.

Alerts are routed based on severity. For example, if a Rule is configured with a `Critical`, it will dispatch alerts to the default destinations configured to handle `Critical` alerts. A single alert may also dispatch to multiple destinations simultaneously, such as creating a Jira ticket, sending an email, and paging the on-call.

## Creating a New Destination

Navigate to Settings > Destinations and select `ADD DESTINATION`.

![](../.gitbook/assets/default-destinations-new.png)

You will then be prompted to select a destination type. Multiple destinations of the same type may be configured, such as several Slack channels or email addresses. This allows for more fine grained control of destination routing.

![Select the destination type](../../.gitbook/assets/destination-types.png)

Next, add a `Display Name` to distinguish the destination from others in the Panther UI and select the associated severities for this destination.

Each destination type will have specific configuration options based on the system's API. See the destination specific setup instructions in the following pages for more details.

![Configure the destination's settings](../../.gitbook/assets/destination-settings-example.png)

Finally, click the `ADD DESTINATION` button to save the configuration. You are now ready to receive alerts!

## Modifying or Deleting Destinations

An existing destination may be modified or deleted by selecting the triple dot button. From here, you can modify the display name, the severities, and the specific configurations. Alternatively, you can also delete the destination.

![Changing a destination](../../.gitbook/assets/destination-modificaiton.png)
