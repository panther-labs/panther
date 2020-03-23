# IAM Setup

The first step is creating the IAM role with access to the S3 buckets containing logs:

![](../../.gitbook/assets/logingestioniam.png)

## Setup

From **Settings**, click **Sources**, then click **ADD SOURCE** under **Log Sources.**

![](../../.gitbook/assets/screen-shot-2020-01-17-at-4.33.47-pm.png)

Enter the details for the logs:

- `Label`: Required. Friendly name of the AWS Account
- `Related Account ID` : Required. The 12-digit AWS Account ID where the S3 buckets are located
- `S3 Buckets`: Required. The names of the S3 buckets that contain the logs
- `KMS Keys`: Optional. In case your data are encrypted using KMS-SSE, provide the ARNs of the KMS keys that the data were encrypted with

![](../../.gitbook/assets/screen-shot-2020-01-21-at-2.04.06-pm.png)

Once you have filled the information, click on **Next**.

Click the **Launch Stack** button to deploy the CloudFormation stack giving Panther Read permissions

![](../../.gitbook/assets/screen-shot-2020-01-21-at-2.09.36-pm.png)

When you click the **Launch Stack** button, a new tab will open in your browser and take you to the AWS Console. Make sure you sign in the AWS Account that was provided in the step above.

![](../../.gitbook/assets/screen-shot-2020-01-21-at-2.15.31-pm.png)

{% hint style="info" %}
Check the acknowledgement in the Capabilities box in the Create stack page
{% endhint %}

Click the **Create stack** button. After few seconds, the stack's `Status` should change to `CREATE_COMPLETE`. If there is an error creating the stack, then an IAM role with the same name may already exist in your account.

![](../../.gitbook/assets/screen-shot-2020-01-21-at-5.26.49-pm.png)

Get back to Panther browser tab and click on **Next,** then **Add New Source** to complete the setup.

{% hint style="success" %}
Congratulations! You have granted Panther the permissions to process your logs in S3.
{% endhint %}

The next sections we will detail how to configure SNS notifications so Panther can analyze new logs as they are delivered to S3.
