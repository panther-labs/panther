---
description: >-
  This page offers an overview of how to implement Automatic Remediation with
  Panther.
---

# Background

## Background

Panther supports near real-time Automatic Remediation of non-compliance resources. This ensures that your infrastructure is as secure as possible.

Panther works by:

- Associating a specific Remediation ID in a given Policy
- When a Policy failure occurs, the `aws-remediation` Lambda function is invoked by Panther
- The `aws-remediation` Lambda assumes a role in the target account with the offending resource and performs the remediation

The following diagram shows how Panther supports Automatic Remediation:

![](../.gitbook/assets/autoremediationmulticustomeraccount.png)

## Installation

Panther's Automatic Remediation Lambda Function is available for download and installation with the AWS Serverless Application Repository. To simplify installation, we have provided a predefined CloudFormation Template that can be installed with just one click.

1. From the Panther Dashboard, go to Setup &gt; AWS &gt; Auto Remediation
2. Click the `Launch Stack` button
3. Create the Stack, and validate that it ran successfully
4. Copy the `LambdaARN` from the Stack's Outputs into the text box in the Panther UI, and hit `Complete Setup`

## IAM Roles Setup

After completing the [StackSet prerequisite setup](https://app.gitbook.com/@panther-labs/s/documentation/~/drafts/-LkkEhww0Zhkfy6WIUs_/primary/amazon-web-services/aws-setup/real-time-events#prerequisites), perform the following to install the IAM Roles used for remediation in each AWS account:

1. Login to the `Administrator` AWS account
2. Navigate to the [CloudFormation Create StackSets](https://us-west-2.console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacksets/create) page
3. Select `Template is ready`
   1. Under `Template source` select `Amazon S3 URL` and paste in the following: `https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-remediation-role/latest/template.yml`
   2. Click `Next`
4. Name the StackSet `panther-remediation-role`. Click `Next`
5. Under the Permissions tab, add the following:
   1. IAM admin role name: `PantherCloudFormationStackSetAdminRole`
   2. IAM execution role name: `PantherCloudFormationStackSetExecutionRole`
   3. Click `Next`
6. Type the AWS Account Ids of the Administrator and Target Accounts in the Account numbers field, separated by commas
   1. Select the same region used above when installing the Lambda function. This can alternatively be in any region where you normally manage CloudFormation templates since the IAM Role resource is global
   2. Set `Maximum concurrent accounts` to 5
   3. Click `Next`
7. Click `Submit` at the bottom of the page to create the StackSet
