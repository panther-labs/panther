---
description: Get started with Panther in 15 minutes
---

# Quick Start

## Prerequisites

What you'll need:

1. An AWS Account
2. An IAM user or role with permissions to create and manage the necessary resources

We've provided a deployment role for your convenience, but any sufficiently privileged role will work:

- [AWS CloudFormation Template](https://panther-public-cloudformation-templates.s3-us-west-2.amazonaws.com/panther-deployment-role/latest/template.yml)
- [Terraform](https://github.com/panther-labs/panther/tree/master/deployments/auxiliary/terraform/panther-deployment-role.tf)

{% hint style="info" %}
We recommend deploying Panther into its own dedicated AWS account.
{% endhint %}

## Deployment
Navigate to the AWS CloudFormation console and create a new stack. The template URL is of the following form:

```
https://panther-EDITION-REGION.s3.amazonaws.com/VERSION/panther.yml
```

where:

* EDITION is `community` or `enterprise`
* REGION is one of: `us-east-1`, `us-east-2`, or `us-west-2`
    * Be sure the template region matches the region in which you are deploying Panther
    * Additional regions are available when [deploying from source](development.md#supported-regions)
* VERSION is the latest [tagged release](https://github.com/panther-labs/panther/releases)

For example:

![CloudFormation Template URL](.gitbook/assets/cfn-deploy-1.png)

On the next page, choose a stack name (e.g. "panther") and configure the name and email for the first Panther user:

![CloudFormation Parameters](.gitbook/assets/cfn-deploy-2.png)

This is just the initial admin user account - you can edit the user and invite additional users after Panther is deployed.
You can also set the CompanyDisplayName here if you like. All other parameters can be ignored.

On the next page, you can skip all the advanced stack settings. Acknowledge the warnings and deploy the stack!

![CloudFormation Finish](.gitbook/assets/cfn-deploy-3.png)

### Using a Template

Alternatively, you can deploy Panther as a nested stack in your own CloudFormation template:

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: My Panther deployment

Resources:
  Panther:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub https://panther-community-${AWS::Region}.s3.amazonaws.com/v1.4.0/panther.yml
      Parameters:
        CompanyDisplayName: AwesomeCo
        FirstUserEmail: user@example.com
        FirstUserGivenName: Alice
        FirstUserFamilyName: Jones
```

Or, to build and deploy from source, see the [development](development.md) page.

## First Login

Once the deployment has finished, you will get an invitation email from `no-reply@verificationemail.com` with your temporary login credentials.
(If you don't see it, be sure to check your spam folder.)

{% hint style="warning" %}
By default, Panther generates a self-signed certificate, which will cause most browsers to present a warning page:

![Self-Signed Certificate Warning](.gitbook/assets/self-signed-cert-warning.png)

Your connection _is_ encrypted, and it's generally safe to continue. However, the warning exists because self-signed certificates do not protect you from man-in-the-middle attacks; for this reason production deployments should provide their own `CertificateArn` parameter value.
{% endhint %}

## Onboarding

Congratulations! You are now ready to use Panther. Follow the steps below to complete your setup:

1. Invite your team in `Settings` > `Users` > `Invite User`
1. Configure [destinations](destinations) to receive generated alerts
2. Onboard data for [real-time log analysis](log-analysis/log-processing/)
3. Write custom [detection rules](log-analysis/rules/) based on internal business logic
4. Onboard accounts for [cloud security scans](policies/scanning/)
5. Write [policies](policies/cloud-security-overview.md) for supported [AWS resources](policies/resources/)
6. Query collected logs with [historical search](historical-search/README.md)



## Removing Panther
To uninstall Panther, simply delete the main "panther" stack (substituting whatever stack name you chose during deployment).
This will automatically remove everything except:

* S3 buckets and their data
* A few empty CloudWatch log groups

You can easily find and delete these manually, or you can run `mage teardown` (see [development](development.md#teardown)).
