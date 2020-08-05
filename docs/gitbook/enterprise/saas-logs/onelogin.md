# OneLogin Setup

Panther is able to process OneLogin events through [OneLogin's integration](https://www.onelogin.com/blog/aws-eventbridge-integration) with Amazon EventBridge.
This allows Panther to process OneLogin logs in a scalable and reliable, low latency manner.  

In order for Panther to process your OneLogin logs, you need to configure your OneLogin account to send data to Amazon EventBridge in Panther AWS account. 

### Configure OneLogin to send data to Amazon EventBridge

1. Log in to OneLogin Administration console
1. Go to **Developers > Webhooks**
1. Go to **New Webhook > Event Webhook for Amazon EventBridge**
1. Add a friendly name e.g. `Panther Integration`
1. Add the AWS AccountId and AWS region where you have deployed Panther. Click on **Save**
1. Click on the new integration that got just created.

### Configure Amazon EventBridge in your account

1. Log in to your AWS Console, in the AWS account where you have deployed Panther
1. Go to **Amazon EventBridge** service in the region where you have deployed Panther
1. Go to **Events > Partner event sources**
1. Keep a note of the OneLogin source (will be in the form `aws.partner/onelogin.com/US-142470/bad86aa8d3`) 
1. Select the OneLogin source, click **Associate with event bus**
1. In the next page, you don't need to select any of the options. Just click **Associate**

### Create a new OneLogin source in Panther

1. Login to your Panther account
1. Click **Log analysis** on the sidebar menu
1. Click **Sources**
1. Click **Add Source**
1. Select **Amazon EventBridge** from the list of available types
1. Enter a friendly name for the source (e.g. `My OneLogin logs`)
1. Select **OneLogin** as log type
1. Add the Bus name that you kept note of earlier. 
1. Save the source!
