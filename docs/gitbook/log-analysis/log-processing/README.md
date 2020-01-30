---
description: >-
  This page shows how to run Panther Rules to analyze event logs from sources
  such as AWS CloudTrail, VPC Flow Logs, S3 Server Access Logs, and more.
---

# Log Processing

## Background

Log processing is a cornerstone requirement when building or improving visibility into your environment. In this section, we'll show how Panther's architecture gives you the ability to collect and transform event log data from different sources into meaningful data for analysis.

## **How It Works**

The following illustration gives a high-level snapshot of how Panther can aggregate and process event logs from different sources such as AWS CloudTrail, VPC Flow Logs, and S3 Server Access Logs:

![](../../.gitbook/assets/logprocessingingestion-4.jpg)

The core macro steps Panther follows to analyze event logs are:

1. You write whatever logs you want Panther to process into an S3 bucket
2. Whenever new logs are written into S3, the bucket sends an event to an SNS Topic
3. There is an SQS Queue in the Panther Master account that is subscribed to the SNS Topic, and receives a message containing the information about what new logs were written and to what bucket
4. A Lambda Function in the Panther Master Account pulls messages off the Queue, and determines what S3 bucket has new log data to process
5. The Lambda Function assumes an IAM Role in the Log Source account and gets the new log data
6. The Lambda Function sends the newly collected log data into the Log Processing pipeline

## **How to Setup Log Processing**

Follow the steps below to setup log processing

- [Setup the Log Processing Role](iam-setup.md)
- [Setup S3 Event notifications and SNS subscription](notifications-setup.md)

## Viewing the Logs

Once you have setup log processing, checkout Panther's [Historical Search](../../historical-search/untitled.md)!
