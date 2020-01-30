---
description: AWS costs associated with running Panther
---

# Costs

Panther is proud to be built entirely on modern serverless technologies. A huge benefit of serverless
designs is their low-cost, usage-based pricing. As a result, Panther is quite cheap to deploy and
you won't have to pay for most AWS services until you onboard data!

However, some infrastructure has an ongoing cost regardless of usage. Our best estimate is that
Panther has a minimum AWS bill of about $20/month while it's deployed, depending on your AWS region 
and Panther configuration settings. For example, Panther creates a custom KMS key for SQS encryption, 
which has a fixed cost of $1/month. But the main running cost is associated with running the web
application continuously in Fargate.

## Front-end web server

In order to serve the web application, an ECS Fargate service (named `panther-web`) has a single
task running, which acts as a front-end server. By default, this task gets allocated 0.5 vCPU and 1024MB
of memory. This leads to a monthly cost of **$14.57 (vCPU) + $3.2 (RAM) = \$17.77** according to the [official ECS pricing page](https://aws.amazon.com/fargate/pricing/).

This means that even if you don't actually use Panther at all, you will still be asked to pay
**\$17.77** for the cost of running an elastic service. If you want to lower this cost
(in exchange for a slower server and an increased web application loading time), you can
modify the parameters found in [panther_config.yml](https://github.com/panther-labs/panther/blob/master/deployments/panther_config.yml). Specifically,
you can lower `WebApplicationFargateTaskCPU` to `256`, lower `WebApplicationFargateTaskMemory` to `512` and deploy (or re-deploy) Panther.

These values are the min allowed values that the front-end server can receive and they will drop the costs
associated with it, down to **\$8.88** per month.
