# Cost Analysis

This page breaks down the cost for each major component within Panther.

## Overview

Panther is proudly built with modern, serverless technologies, with the benefit of low-cost, usage-based pricing. As a result, Panther is cost-effective and will run within the Free Tier until you onboard data to analyze. Panther is also deployed within your AWS account for maximum control on data governance.

However, some infrastructure has an ongoing cost regardless of usage. For example, Panther creates a custom KMS key for SQS encryption, which has a fixed cost of \$1/month. The main cost comes from running the web application continuously with ECS Fargate, continually analyzing data with Lambda, and storing parsed logs in S3.

## Frontend

To serve the web application, an ECS Fargate service named `panther-web` runs a single task for the front-end server. By default, this task is allocated 0.5 of vCPU and 1024MB of memory, which leads to a monthly cost of $14.57 (vCPU) + $3.2 (RAM) = \$17.77 according to the [official ECS pricing page](https://aws.amazon.com/fargate/pricing/).

This means that the minimum cost of running the container is **\$17.77/month**. If you want to lower this cost in exchange for a slower server and an increased load time, you can modify the parameters found in the [panther_config.yml](https://github.com/panther-labs/panther/blob/master/deployments/panther_config.yml).

Specifically, you can make the following changes:

- Set `WebApplicationFargateTaskCPU` to `256`
- Set `WebApplicationFargateTaskMemory` to `512`

Then, deploy (or redeploy) Panther.

These values are the minimum allowed values for the front-end, and they will decrease the cost down to **\$8.88/month**.

## Log Processing

A majority of Panther's log analysis cost comes from S3 storage. Because of Panther's design, compute cost is minimal and avoids usage of expensive services.

Monthly cost estimation:
* **1 TB/day = 30 TB/month**
* Compute (~$50) + Storage (~$3000) = **$(3,050)/month**

This cost is further reduced by purchasing a Panther Enterprise license, which uses additional data optimizations for teams who need higher scale.

Contrasting to other solutions such as Splunk or Sumo Logic:
* 1 TB/day x ~$100/GB = **$100,000/month**
