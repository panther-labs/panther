# Cloud Security Setup

Panther can scan any number of AWS accounts. Each cloud resource is associated with the related account's label \(Prod, Dev, Test, etc\).

## Add Your Accounts

The first step is to add a new AWS account source by navigating to `Cloud Security` > `Sources` > `Add Account`:

![](../.gitbook/assets/cloud-security/setup1.png)

Enter your account `Name` and `AWS Account ID`.

{% hint style="info" %}
If you want to enable real-time scans or automatic remediation, make sure to tick the boxes here!
{% endhint %}

![](../.gitbook/assets/cloud-security/setup2.png)

Click `Next`, then download the generated template or click directly into the CloudFormation Console:

![](../.gitbook/assets/cloud-security/setup3.png)

Clicking the `Launch Stack` button will open [CloudFormation](https://aws.amazon.com/cloudformation/) in the AWS account you are currently logged into with pre-populated stack variables:

![](../.gitbook/assets/cloud-security/setup-cfn.png)

{% hint style="info" %}
Make sure to check the acknowledgement in the `Capabilities`box
{% endhint %}

![](../.gitbook/assets/cloud-security/setup-cfn-2.png)

Click the `Create stack` button. After about 15 seconds, the stack's `Status` should change to `CREATE_COMPLETE`. If there is an error creating the stack, then an IAM role with the same name may already exist in your account.

![](../.gitbook/assets/cloud-security/setup-cfn-3.png)

Back in the UI, click `Next`, then `Save Source` to complete this setup:

![](../.gitbook/assets/cloud-security/setup4.png)

## Configure Real-Time Monitoring

The next section will detail how to monitor changes to AWS resources in real-time.

### Prerequisites

To configure real-time events to Panther from multiple regions and accounts, we can use [AWS CloudFormation StackSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html).

The following diagram illustrates this with an example model:

![](../.gitbook/assets/cloud-security/setup-stackset-overview.png)

### Plan Your Account Layout

In this case, the account running Panther will act as the `Administrator` account to manage stack creation and updates.

All other accounts to onboard will act as `Target` accounts to send CloudWatch logs to Panther.

{% hint style="info" %}
The `Administrator` account may also be the `Target` account. To run and scan a single AWS account, this will always be the case, and both IAM roles are required.
{% endhint %}

### Setup Administrator Account

First, create the CloudFormation StackSet Admin role in the main Panther account to manage the deployment of real-time events in your target accounts.

From the CloudFormation Console, create a new stack, select `Template is ready`, and enter the following `Amazon S3 URL`:

```
https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-stackset-iam-admin-role/latest/template.yml
```

Click the acknowledgements and create the stack.

This IAM role allows the CloudFormation StackSet to assume roles in target accounts and orchestrate the configuration of real-time events:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::*:role/PantherCloudFormationStackSetExecutionRole-<PantherRegion>",
            "Effect": "Allow"
        }
    ]
}
```

{% hint style="info" %}
This IAM Role is only assumable by the Panther Deployment account.
{% endhint %}

### Onboard Accounts

{% hint style="warning" %}
In order for target accounts to be onboarded, you must have checked the "Real-Time AWS Resource Scan" box during the account setup.
{% endhint %}

Login to the `Administrator` account's AWS Console, and open the [CloudFormation StackSets](https://us-west-2.console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacksets) page:

![](../.gitbook/assets/cloud-security/setup-stacksets-1.png)

Click the `Create StackSet` button on the top right, select `Template is ready`, and enter the following `Amazon S3 URL`:

```
https://s3-us-west-2.amazonaws.com/panther-public-cloudformation-templates/panther-cloudwatch-events/latest/template.yml
```

Click `Next`.

Name the StackSet `panther-real-time-events`.

Enter the 12-digit AWS Account ID where Panther is deployed in the `MasterAccountId` field.

In the `QueueArn` field, paste the following \(substituting the AWS account ID of the account running Panther\):

```
arn:aws:sqs:<PantherRegion>:<PantherAccountID>:panther-aws-events-queue
```

Click `Next`.

![](../.gitbook/assets/cloud-security/setup-stacksets-2.png)

Under the Permissions tab, add the IAM admin role name:

```
PantherCloudFormationStackSetAdminRole-<MASTER_ACCOUNT_REGION>
```

And the IAM execution role name:

```
PantherCloudFormationStackSetExecutionRole-<MASTER_ACCOUNT_REGION>
```

Click `Next`.

![](../.gitbook/assets/cloud-security/setup-stacksets-3.png)

Add the AWS Account IDs of the Target Accounts in the Account numbers field, separated by commas.

Select `Add all regions` or a list of desired regions, set `Maximum concurrent accounts` to 5, and click `Next`.

Click `Submit` at the bottom of the page to create the StackSet.

To check on the status of the StackSet, check the `Operations` tab:

![](../.gitbook/assets/cloud-security/setup-stacksets-4.png)

{% hint style="success" %}
Awesome! You should now have real-time CloudWatch events sending to Panther.
{% endhint %}

### Adding Additional Accounts

To add more accounts to the StackSet above, use the following steps:

{% hint style="warning" %}
Make sure you have at least one AWS Account Source configured with the `DeployCloudWatchEventSetup`set to`true`
{% endhint %}

1. Sign in to the `Administrator` account's AWS Console
2. On the [CloudFormation StackSets](https://us-west-2.console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacksets) page, select the `panther-real-time-events` StackSet
3. Select the `Actions` button on the top right and select `Add new stacks to StackSet`
4. Add the new AWS account ID's into the Account numbers field, specify regions, and click through to the `Submit` button
