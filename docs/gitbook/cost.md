---
description: AWS costs of running Panther
---

# Costs

Panther is proudly built with modern, serverless technologies, with the benefit of low-cost, usage-based pricing. As a result, Panther is quite cheap to deploy and will run within the Free Tier until you onboard data.

However, some infrastructure has an ongoing cost regardless of usage. Our estimate is that Panther has a minimum AWS bill of about \$20/month, depending on your AWS region and configuration settings.

For example, Panther creates a custom KMS key for SQS encryption, which has a fixed cost of \$1/month. The main cost comes from running the web application continuously with ECS Fargate, with additional information provided below.

## Front-End Web Server

In order to serve the web application, an ECS Fargate service (named `panther-web`) runs a single task for the front-end server. By default, this task is allocated 0.5 of vCPU and 1024MB of memory, which leads to a monthly cost of **$14.57 (vCPU) + $3.2 (RAM) = \$17.77** according to the [official ECS pricing page](https://aws.amazon.com/fargate/pricing/).

This means that the minimum cost of running the container is **\$17.77/month**. If you want to lower this cost in exchange for a slower server and an increased load time, you can modify the parameters found in the [panther_config.yml](https://github.com/panther-labs/panther/blob/master/deployments/panther_config.yml).

Specifically, you can make the following changes:

- Set `WebApplicationFargateTaskCPU` to `256`
- Set `WebApplicationFargateTaskMemory` to `512`

Then, deploy (or re-deploy) Panther.

These values are the minimum allowed values for the front-end, and they will decrease the cost down to **\$8.88/month**.

## Backend Lambda Functions

{% hint style="info" %}
Coming soon
{% endhint %}
