# Log Processing

## Overview

Log processing can improve visibility into your environments by monitoring log events in real time.

In this section, we'll show how Panther's architecture gives you the ability to collect and transform raw logs into meaningful data for analysis.

## **How It Works**

The following illustration provides a high-level architecture of how Panther aggregates and processes event logs from different sources.

![](../../.gitbook/assets/logprocessingingestion-4.jpg)

The high-level steps are:

1. Logs are written into an S3 bucket
2. The bucket sends an S3 event notification to an SNS Topic
3. There is an SQS Queue in the Panther Master account that is subscribed to the SNS Topic which receives the event notification
4. A Lambda Function pulls messages off the Queue and assumes an IAM Role to download the new log data
6. A Lambda Function sends the parsed log data to the Log Analysis pipeline

## **How to Setup Log Processing**

First, data must send to an S3 bucket. We recommend organizing incoming data by using S3 folders or separate buckets. You can onboard as many buckets as you would like from any region.

Follow the steps below to set this up across your AWS accounts:
- [Log Processing IAM Setup](iam-setup.md)
- [S3 Event Notifications and SNS Setup](notifications-setup.md)

## Viewing the Logs

Once log processing is setup, your data can be searched with [Historical Search](../../historical-search/README.md)!
