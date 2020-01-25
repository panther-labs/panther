---
description: >-
  This page shows how to configure Panther to perform baseline and periodic
  scans of your AWS account
---

# Scanning

## How It Works

When onboarding a new AWS account for compliance, Panther conducts a baseline scan to compile existing resources in your account. Resource changes are tracked in real-time and scans periodically run on your account to ensure the most consistent state possible.

This functionality is enabled by creating a [read-only IAM Role](https://docs.aws.amazon.com/general/latest/gr/aws-security-audit-guide.html) and [AWS CloudWatch Event Rules](https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/WhatIsCloudWatchEvents.html) to stream real-time events. Automatic remediation can also be configured to reactively fix insecure infrastructure.

Panther can scan as many AWS accounts as you would like. Each resource is associated with the account's label \(Prod, Dev, Test, etc\).

## Setup Scans

Follow the steps below to setup scanning for each AWS account.

- Deploy the [Scan Role](aws-compliance-setup.md)
- Deploy [Real-Time Events](real-time-events.md)
- Setup [Automatic Remediation](../../automatic-remediation/automatic-remediation.md) \(Optional\)

![Architecture Diagram](../../.gitbook/assets/snapshot-processing-v3.png)

##
