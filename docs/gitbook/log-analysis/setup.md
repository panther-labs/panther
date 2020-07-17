# Log Analysis Setup

## Set Up Permissions to Pull Data

The steps below will enable secure access for Panther to pull security logs from S3 bucket(s).

From **Log Analysis**, click **Sources**, then **Onboard Your Logs**:

![](../.gitbook/assets/log-analysis-iam-1.png)

### Step 1: Enter the Bucket Details

|         Field         | Required? | Description                                                                                |
| :----------------------: | ----------------------------------------------------------------------------------------- | --------|
|  `Name`   | `Yes` | Friendly name of the S3 bucket |
| `Account ID`   | `Yes`  | The 12-digit AWS Account ID where the S3 buckets are located |
| `Bucket Name` | `Yes`  | The S3 Bucket ID/name to onboard |
| `Log Types`   | `Yes`  | The list of Log Types contained in the bucket  |
| `S3 Prefix Filter`   | `No`  | The path of the files to analyze, which should not start with the `/` character   |
| `KMS Key`   | `No`  | If your data is encrypted using KMS-SSE, provide the ARN of the KMS key  |

![](../.gitbook/assets/log-analysis-iam-2.png)

Click **Next**.

### Step 2: Deploy the CloudFormation Stack

You can deploy the generated stack by either **launching the CloudFormation Console** or **downloading the template** and applying it through your own pipeline.

![](../.gitbook/assets/log-analysis-iam-3.png)

When you click the **Launch console** link, a new tab will open in your browser and direct you to the AWS Console for the account you are currently logged into.

{% hint style="info" %}
Make sure you are signed into the AWS Account where you'd like to deploy the stack.
{% endhint %}

![](../.gitbook/assets/log-analysis-iam-4.png)

{% hint style="info" %}
Make sure to check the acknowledgement in the Capabilities box on the bottom
{% endhint %}

Click the **Create stack** button. After few seconds, the stack's `Status` should change to `CREATE_COMPLETE`. If there is an error creating the stack, then either an IAM role with the same name already exists, or you don't have enough permissions to create the role.

### Step 3: Save the Source

Head back to Panther and click on **Next,** then **Save Source** to complete the setup.

![](../.gitbook/assets/log-analysis-iam-5.png)

{% hint style="success" %}
Congratulations! You have granted Panther the permissions to process your logs in S3.
{% endhint %}

## Setup Notifications of New Data

Now that Panther has the ability to pull log data, you need to configure your S3 buckets to send [notifications](https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html) when new data arrives.

### Existing S3 Buckets

First, create an SNS Topic and SNS Subscription to notify Panther that new data is ready for processing:

#### Create SNS Topic

Log into the AWS Console of the account that owns the S3 bucket. Select the AWS Region where your S3 buckets are located, navigate to the **CloudFormation** console, and click on **Create Stack** (with new resources).

![](../.gitbook/assets/create-sns-topic-1.png)

Under the `Specify template` section, enter the following Amazon S3 URL:

```
https://panther-public-cloudformation-templates.s3-us-west-2.amazonaws.com/panther-log-processing-notifications/latest/template.yml
```

![](../.gitbook/assets/create-sns-topic-2.png)

Specify the stack details below:

|         Field         | Description                                                                                |
| :----------------------: | ----------------------------------------------------------------------------------------- |
| `Stack name`    | A name of your choice, e.g. `panther-log-processing-notifications-<bucket-label>` |
| `MasterAccountId`     | The 12 digit AWS Account ID where Panther is deployed |
| `PantherRegion`   | The region where Panther is deployed |
| `SnsTopicName`     | The name of the SNS topic receiving the notification, by default this is `panther-notifications-topic`  |

Click on **Next**, **Next**, and then **Create Stack**.

This stack has one output named `SnsTopicArn`.

#### Configure Event Notifications

With the SNS Topic created, the final step is to enable notifications from the S3 buckets.

Navigate to the AWS [S3 Console](https://s3.console.aws.amazon.com/s3/home), select the relevant bucket, and click the `Properties` tab.

From there, find the `Events` card under the `Advanced settings` section. Click `+ Add notification` and use the following settings:

|         Field         | Value                                                                                |
| :----------------------: | ----------------------------------------------------------------------------------------- |
| `Name`    | `PantherEventNotifications` |
| `Events`     | `All object create events` |
| `Send to`   | `SNS Topic` |
| `SNS`     | `panther-notifications-topic`  |
| `Suffix`   | (optional) limits notifications to objects with keys that end in matching characters  |
| `Prefix`   | (optional) limits notifications to objects with keys that start with matching characters  |

Click `Save`.

##### Using CloudFormation

This can also be accomplished using CloudFormation with the following examples:

```yaml
Resources:
 CloudTrailBucket:
   Type: AWS::S3::Bucket
   Properties:
     BucketName: <my-cloudtrail-bucket>
     NotificationConfiguration:
       TopicConfigurations:
         - Topic: arn:aws:sns:<PantherRegion>:<MasterAccountId>:panther-notifications-topic
           Event: s3:ObjectCreated:*
```

```json
{
 "Resources": {
   "CloudTrailBucket": {
     "Type": "AWS::S3::Bucket",
     "Properties": {
       "BucketName": "my-cloudtrail-bucket",
       "NotificationConfiguration": {
         "TopicConfigurations": {
           "Topic": "SNS-TOPIC-ARN",
           "Event": "s3:ObjectCreated:*"
         }
       }
     }
   }
 }
}
```

### Existing S3 Buckets and SNS Topics

Follow the steps below if you already have an S3 bucket configured to send `All object create events` to an SNS Topic.

#### Modify SNS Access Policy

Create a subscription between your SNS topic and Panther's log processing SQS queue.

1. Log into the AWS Console for the account where your S3 bucket exists
2. Navigate to the [SNS Console](https://us-west-2.console.aws.amazon.com/sns/v3/home#/topics) and select the SNS Topic currently receiving events
3. Note the ARN of this SNS topic
4. Select the `Edit` button and scroll down to the `Access Policy` card
5. Add the statement shown below to the topic's `Access Policy`. Populate `<PANTHER-MASTER-ACCOUNT-ID>` with the 12-digit account ID where Panther is deployed. Populate `SNS-TOPIC-ARN` with the ARN you noted on step \#3:

```yaml
Sid: CrossAccountSubscription
Effect: Allow
Principal:
  AWS: arn:aws:iam::<PANTHER-MASTER-ACCOUNT-ID>:root
Action: sns:Subscribe
Resource: <SNS-TOPIC-ARN>
```

```json
{
  "Sid": "CrossAccountSubscription",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::<MasterAccountId>:root"
  },
  "Action": "sns:Subscribe",
  "Resource": "<SNS-TOPIC-ARN>"
}
```

#### Create SNS Subscription

Finally, create the subscription to the Panther Master account's SQS queue.

From the SNS Console, select the `Create subscription` button:

1. `Protocol`: `Amazon SQS`
2. `Endpoint`: `arn:aws:sns:<PantherRegion>:<MasterAccountId>:panther-input-data-notifications-queue`
3. Select the `Create subscription` button

## Log Processing Advanced Configurations

These are just two basic configurations to integrate with Panther Log Processing.

There are other variations and advanced configurations available for more complex use cases and considerations. For example, instead of using S3 event notifications for CloudTrail data you may have CloudTrail directly notify SNS of the new data.

## Viewing Collected Logs

After log sources are configured, your data can be searched with the [Data Analytics](../enterprise/data-analytics/README.md) page!
