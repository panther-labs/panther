---
description: Get started with Panther in 20 minutes
---

# Quick Start

Panther is a collection of serverless applications deployed within your AWS account. The frontend is a React application which runs in a Docker container \(via ECS\), and the backend is a collection of compute \(Lambda\), storage \(DynamoDB / S3\), and other supporting services.

Your data is always under your control, encrypted in transit and at rest. All infrastructure is least-privilege, modeled and deployed with AWS CloudFormation.

{% hint style="info" %}
You can optionally use Panther alongside an existing logging platform such as Splunk or Elasticsearch. We recommend an architecture that tees traffic between both with tools such as Logstash or Fluentd.
{% endhint %}

## Concepts

Before we cover deployment, let's establish the terminology:

- **Event**: A normalized log line from a sources such as CloudTrail, Osquery, or Suricata
- **Rule**: A Python function to detect suspicious activity
- **Resource**: A cloud entity, such as an IAM user, virtual machine, or data bucket
- **Policy:** A Python function representing the desired secure state of a resource
- **Alert**: A notification to the team when a policy has failed or a rule has triggered

## Prerequisites

You need an AWS account and an IAM user or role with permission to create and manage the necessary AWS resources. We provide an IAM role you can use for Panther deployment:

- CloudFormation ([source](https://github.com/panther-labs/panther/tree/master/deployments/auxiliary/cloudformation/panther-deployment-role.yml)): [https://panther-public-cloudformation-templates.s3-us-west-2.amazonaws.com/panther-deployment-role/latest/template.yml](https://panther-public-cloudformation-templates.s3-us-west-2.amazonaws.com/panther-deployment-role/latest/template.yml)
- Terraform ([source](https://github.com/panther-labs/panther/tree/master/deployments/auxiliary/terraform/panther-deployment-role.tf))

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

#### Step 1

Clone the latest release of [Panther](https://github.com/panther-labs/panther):

```bash
git clone https://github.com/panther-labs/panther --depth 1 --branch v0.3.0
cd panther
```

#### Step 2

[Install and run Docker 17+](https://docs.docker.com/install/)

You can verify the docker daemon is running by typing `docker info` in the console or checking the status bar:

![Docker Status](.gitbook/assets/docker-status.png)

From the repo root, start the development environment: `./dev.sh`

{% hint style="info" %}
Your AWS credentials _must_ be exported as environment variables for the docker image running locally on your machine to find them. This also makes it easy to use temporary credential managers like [aws-vault](https://github.com/99designs/aws-vault):

`aws-vault exec <profile> -- ./dev.sh`
{% endhint %}

#### Step 3

Run `mage deploy`

- If you've made any changes to the source files or want to run tests, you may need to first install development dependencies with `mage setup:all`
- If you use `aws-vault`, you must be authenticated with MFA. Otherwise, IAM role creation will fail with `InvalidClientTokenId`
- The initial deployment will take 20-30 minutes. If your credentials timeout, you can safely redeploy to pick up where you left off.
- Near the end of the deploy command, you'll be prompted for your first/last name and email to setup the first Panther user account.
- You'll get an email from `no-reply@verificationemail.com` with your temporary password. If you don't see it, be sure to check your spam folder.

#### Log In

Now you can sign into Panther! The URL is linked in the welcome email and also printed at the end of the deploy command.

{% hint style="warning" %}
By default, Panther generates a self-signed certificate, which will cause most browsers to present a warning page:

![Self-Signed Certificate Warning](.gitbook/assets/self-signed-cert-warning.png)

Your connection _is_ encrypted, and it's generally safe to continue if the domain matches the output of the deploy command. However, the warning exists because self-signed certificates do not protect you from man-in-the-middle attacks; for this reason production deployments should provide their own ACM certificate in the `deployments/panther_config.yml` file.
{% endhint %}

### Deployment Options

Rather than deploying from within a docker container, you can instead configure your [development environment](development.md#manual-installation) locally. This will take more time initially but will lead to faster deployments.

You can also deploy from an EC2 instance with Docker and git installed in the same region you're deploying Panther to. This is typically the fastest option since it minimizes the latency when communicating with AWS services. Instead of exporting your AWS credentials as environment variables, you will need to attach the [deployment IAM role](#prerequisites) to your EC2 instance profile. Your EC2 instance needs at least 1 vCPU and 2GB of memory; the cheapest suitable instance type is a `t2.small`.

## Onboarding

Now you can follow the steps below to configure [alert outputs](destinations/alert-setup/), [cloud security scans](policies/scanning/), and [real-time log analysis](log-analysis/log-processing/)!

#### Log Analysis

- [Log Analysis Setup](log-analysis/log-processing/)
- [Create Rules for supported Log Types](log-analysis/rules/)

#### Cloud Security

- [Background](policies/compliance-background.md)
- [Cloud Security Scanning Setup](policies/scanning/)
- [Create Policies](policies/compliance-background.md) for the supported [AWS Resources](policies/resources/)

## Support

- [Report Bugs](https://github.com/panther-labs/panther/issues)
- [Chat with the Panther Labs Team on Slack](https://panther-labs-oss-slackin.herokuapp.com/)
- [Contact Sales for Enterprise Support](https://runpanther.io/request-a-demo/)
