# Log Processing

## Overview

Log analysis can improve visibility into your environments by monitoring events in real time, such as:

* Login/Logout
* API calls
* Network traffic
* Running processes
* System changes
* Output from IDS sensors

 In this section, we'll show how Panther gives you the ability to collect and transform logs into meaningful insights.

## How It Works

![](../../.gitbook/assets/logprocessingingestion-4.jpg)

1. Logs are written into an S3 bucket
2. The bucket sends an S3 event notification to an SNS Topic
3. An SQS Queue in the Panther Master account receives the event notification
4. A Lambda function pulls messages off the Queue, assumes an IAM Role, and downloads the log data
6. A Lambda function sends the parsed log data for analysis

## How to Setup Log Processing

First, the data you'd like to analyze must be sent to an S3 bucket.

We recommend organizing incoming data by using S3 folders or multiple buckets.

You can onboard as many buckets as you would like from any region.

Get started with the pages below:
- [Log Processing IAM Setup](iam-setup.md)
- [S3 Event Notifications and SNS Setup](notifications-setup.md)

## Viewing the Logs

After log analysis is setup, your data can be searched with [Historical Search](../../historical-search/README.md)!
