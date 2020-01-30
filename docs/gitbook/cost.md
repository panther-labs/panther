---
description: Costs associated with Panther
---

# Costs

Panther is proud to be mostly implemented on serverless technologies. This means that you will only pay for your use
of the product and won't be charged when you don't use it.

Unfortunately, some pieces of our software solution require infrastructure continuously "running", which
means that there is going to be a minimum monthly cost associated with the deployment of our product in your
AWS Account.

The following sections analyze & associate this cost with the related technologies.

## Front-end web server

In order to serve you a web application, an ECS FARGATE service (named `panther-web`) has a single
task running, which acts as a front-end server. By default this task gets allocated 0.5 vCPU and 1024MB
of memory. This leads to a monthly cost of **$14.57 (vCPU) + $3.2 (RAM) = \$17.77** according to the [official ECS pricing page](https://aws.amazon.com/fargate/pricing/).

This means that even if you don't actually use Panther at all, you will still be asked to pay
**\$17.77** for the cost of running an elastic service. If you want to lower this cost
(in exchange for a slower server and an increased web application loading time), you can
modify the parameters found in [panther_config.yml](https://github.com/panther-labs/panther/blob/master/deployments/panther_config.yml). Specifically,
you can lower `WebApplicationServerCpu` to `256`, lower `WebApplicationServerMemory` to `512` and deploy (or re-deploy) Panther.

These values are the min allowed values that the front-end server can receive and they will drop the costs
associated with it, down to **\$8.88** per month.
