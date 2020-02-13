---
description: Get started with Panther in 20 minutes
---

# Quick Start

Welcome to the future of open-source cloud security - we're glad you're here!

Panther is a collection of serverless applications deployed within your AWS account. The frontend is a React application which runs in a Docker container \(via ECS\), and the backend is a collection of compute \(Lambda\), storage \(DynamoDB / S3\), and other supporting services.

Your data is always under your control, encrypted in transit and at rest. All infrastructure is least-privilege, modeled and deployed with AWS CloudFormation.

{% hint style="info" %}
You can optionally use Panther alongside an existing logging platform such as Splunk or ElasticSearch. We recommend an architecture that tees traffic between both with tools such as Logstash or Fluentd.
{% endhint %}

## Concepts

Before we cover deployment, let's establish the terminology:

- **Event**: A normalized log line from a sources such as CloudTrail, Osquery, or Suricata
- **Rule**: A Python function to detect suspicious activity
- **Resource**: A cloud entity, such as an IAM user, virtual machine, or data bucket
- **Policy:** A Python function representing the desired secure state of a resource
- **Alert**: A notification to the team when a policy has failed or a rule has triggered

## Prerequisites

You need an AWS account and an IAM user or role with permission to create resources in Lambda, DynamoDB, S3, ECS, ELB, EC2 \(security groups, subnets, VPC\), SNS, SQS, SES, KMS, IAM, CloudFormation, CloudWatch, API Gateway, Cognito, and AppSync.

{% hint style="info" %}
Precise deployment policy coming soon!
{% endhint %}

_We recommend deploying Panther into its own AWS account via_ [_AWS Organizations_](https://aws.amazon.com/blogs/security/how-to-use-aws-organizations-to-automate-end-to-end-account-creation/)_. This ensures that detection infrastructure is contained within a single place._

### Supported AWS Regions

Panther relies on dozens of AWS services, some of which are not yet available in every region. In particular, AppSync, Cognito, Athena, and Glue are newer services not available in us-gov, china, and other regions. At the time of writing, all Panther backend components are supported in the following:

- `ap-northeast-1` (tokyo)
- `ap-northeast-2` (seoul)
- `ap-south-1` (mumbai)
- `ap-southeast-1` (singapore)
- `ap-southeast-2` (sydney)
- `ca-central-1` (canada)
- `eu-central-1` (frankfurt)
- `eu-west-1` (ireland)
- `eu-west-2` (london)
- `us-east-1` (n. virginia)
- `us-east-2` (ohio)
- `us-west-2` (oregon)

Consult the [AWS region table](https://aws.amazon.com/about-aws/global-infrastructure/regional-product-services/) for the source of truth about service availability in each region.

### Configure AWS Credentials

Configure your AWS credentials and deployment region:

```bash
export AWS_REGION=us-east-1  # Choose your region from the list above
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

If you've already configured your credentials with the AWS CLI (you have a `~/.aws/credentials` file), you can easily add them to the environment:

```bash
export AWS_ACCESS_KEY_ID=`aws configure get aws_access_key_id`
export AWS_SECRET_ACCESS_KEY=`aws configure get aws_secret_access_key`
```

{% hint style="warning" %}
Remember to follow best security practices when handling access keys:

- Avoid storing them in plaintext files
- Use IAM roles with temporary session credentials
- Rotate access keys every 90 days
- Enforce MFA for key access

Tools like [aws-vault](https://github.com/99designs/aws-vault) can help with all of the above, check out our [blog post](https://blog.runpanther.io/secure-multi-account-aws-access/) to learn more!
{% endhint %}

## Deployment

Run Panther in 3 easy steps: clone the repo, install docker, and deploy!

First, clone the latest release of the [Panther repo](https://github.com/panther-labs/panther):

```bash
git clone https://github.com/panther-labs/panther --depth 1 --branch v0.2.0
cd panther
```

Next, [install Docker 17+](https://docs.docker.com/install/) and start the application. You can verify the docker daemon is running by typing `docker info` in the console or checking the status bar:

![Docker Status](.gitbook/assets/docker-status.png)

From the repo root, start the development environment: `./dev.sh`

{% hint style="info" %}
Your AWS credentials _must_ be exported as environment variables for the docker image running locally on your machine to find them. This also makes it easy to use temporary credential managers like [aws-vault](https://github.com/99designs/aws-vault):

`aws-vault exec <profile> -- ./dev.sh`
{% endhint %}

{% hint style="info" %}
Rather than deploying from your local machine, you can opt to use an EC2 instance with Docker and
git installed. Instead of exporting your AWS credentials as environment variables, you will need to attach an IAM role to your EC2 instance profile, with enough permissions for the creation of all Panther resources.

The minimum requirements for an EC2 machine are 1 vCPU and 2GB of memory. The lowest-cost instance that satisfies those requirements is an EC2 `t2.small`.
{% endhint %}

{% hint style="info" %}
Rather than deploying from within a docker container, you can instead configure your [development environment](development.md#manual-installation) locally. This will take more time initially but will lead to faster deployments.
{% endhint %}

You're all set! Run `mage deploy`

- The initial deployment will take 20-30 minutes. If your credentials timeout, you can safely redeploy to pick up where you left off.
- Near the end of the deploy command, you'll be prompted for your first/last name and email to setup the first Panther user account.
- You'll get an email from [**no-reply@verificationemail.com**](mailto:no-reply@verificationemail.com) with your temporary password. If you don't see it, be sure to check your spam folder.

Now you can sign into Panther! The URL is linked in the welcome email and also printed at the end of the deploy command.

{% hint style="warning" %}
By default, Panther generates a self-signed certificate, which will cause most browsers to present a warning page:

![Self-Signed Certificate Warning](.gitbook/assets/self-signed-cert-warning.png)

Your connection _is_ encrypted, and it's generally safe to continue if the domain matches the output of the deploy command. However, the warning exists because self-signed certificates do not protect you from man-in-the-middle attacks; for this reason production deployments should provide their own ACM certificate in the `deployments/panther_config.yml` file.
{% endhint %}

## Onboarding

Follow the steps below to onboard data, add AWS accounts, configure alert destinations, and more. The first step is configuring your [alert outputs](destinations/alert-setup/). Then, proceed below to configure scans and real-time log analysis.

#### Log Analysis

- [Log Analysis Setup](log-analysis/log-processing/)
- [Create Rules for supported Log Types](log-analysis/rules/)

#### Cloud Compliance

- [Background](policies/compliance-background.md)
- [Compliance Scanning Setup](policies/scanning/)
- [Create Policies](policies/compliance-background.md) for the supported [AWS Resources](policies/resources/)

## **Support**

- [Report Bugs](https://github.com/panther-labs/panther/issues)
- [Chat with the Panther Labs team on Gitter](https://gitter.im/runpanther/community)
- [Panther Blog](https://blog.runpanther.io/)
- [Panther Website](https://runpanther.io/)
