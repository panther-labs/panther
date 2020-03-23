# Log Analysis Setup

The IAM role created below will allow access to the S3 buckets containing logs:

![](../../.gitbook/assets/logingestioniam.png)

## IAM Setup

From **Log Analysis**, click **Sources**, then **Onboard Your Logs**:

![](../../.gitbook/assets/log-analysis-iam-1.png)

### Step 1 - Enter the Bucket Details

|         Field         | Required? | Description                                                                                |
| :----------------------: | ----------------------------------------------------------------------------------------- | --------|
|  `Name`   | `Yes` | Friendly name of the S3 bucket |
| `Account ID`   | `Yes`  | The 12-digit AWS Account ID where the S3 buckets are located |
| `Bucket Name` | `Yes`  | The S3 Bucket ID/name to onboard |
| `Log Types`   | `Yes`  | The list of Log Types contained in the bucket  |
| `S3 Prefix Filter`   | `No`  | The path of the files to analyze   |
| `KMS Key`   | `No`  | If your data is encrypted using KMS-SSE, provide the ARN of the KMS key  |

![](../../.gitbook/assets/log-analysis-iam-2.png)

#### Optional Details

![](../../.gitbook/assets/log-analysis-iam-2-optional.png)

Once you have filled the information, click on **Next**.

### Step 2 - Deploy the IAM Role

You can deploy the generated IAM role by either **launching the CloudFormation Stack** in the console directly, or **downloading the template** and applying it through your own pipelines.

![](../../.gitbook/assets/log-analysis-iam-3.png)

#### CloudFormation Console

If you click the **Launch Stack** button, a new tab will open in your browser and take you to the AWS CloudFormation Console. Make sure you sign in the same AWS Account that was provided in the previous step.

![](../../.gitbook/assets/log-analysis-iam-4.png)

{% hint style="info" %}
Make sure to check the acknowledgement in the Capabilities box on the bottom
{% endhint %}

Click the **Create stack** button. After few seconds, the stack's `Status` should change to `CREATE_COMPLETE`. If there is an error creating the stack, then an IAM role with the same name may already exist in your account.

### Step 3 - Save the Source

Go back to Panther browser tab and click on **Next,** then **Save Source** to complete the setup.

![](../../.gitbook/assets/log-analysis-iam-5.png)

{% hint style="success" %}
Congratulations! You have granted Panther the permissions to process your logs in S3.
{% endhint %}

## SNS Notification Setup

Now that Panther has the ability to pull data from S3, you must configure your S3 buckets to send [notifications](https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html) on new data.

### Existing S3 Buckets

First, create an SNS Topic and SNS Subscription to notify Panther that new data is ready for processing:

#### Create Notifications SNS Topic

Log into the AWS Console of the account that owns the S3 bucket. Select the AWS Region where your S3 buckets are located, navigate to the **CloudFormation** console, and click on **Create Stack** (with new resources).

Under the `Specify template` section, enter the following Amazon S3 URL:

```
https://panther-public-cloudformation-templates.s3-us-west-2.amazonaws.com/panther-log-processing-notifications/latest/template.yml
```

##### Specify Stack Details

1. `Stack name`: A name of your choice, e.g. `panther-log-processing-notifications-<bucket-label>`
2. `MasterAccountId` : The 12 digit AWS Account ID where Panther is deployed
3. `PantherRegion`: The region where Panther is deployed
4. `SnsTopicName`: The name of the SNS topic receiving the notification, by default is `panther-notifications-topic`

##### Create Stack

Click on **Next** and again **Next**. Click on **Create Stack**. This stack has one output named `SnsTopicArn`

#### Configure Event Notifications

##### Using the Console

Navigate to the AWS [S3 Console](https://s3.console.aws.amazon.com/s3/home), select the relevant bucket, and click the `Properties` tab.

From there, scroll down to the `Advanced settings` section to find the `Events` card, and configure a new event to send `All object create events` to the topic created above (`panther-notifications-topic`)

##### Using CloudFormation

Alternatively, this can be accomplished via CloudFormation by adding the following properties to the relevant S3 bucket resources:

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

Follow the steps below if you have an S3 bucket aggregating data with an SNS Topic receiving `All object create events`.

#### Modify SNS Access Policy

Create a subscription between your SNS topic and Panther's log processing SQS queue.

1. Log into the AWS Console for the account where your S3 bucket exists
2. Navigate to the [SNS Console](https://us-west-2.console.aws.amazon.com/sns/v3/home#/topics) and select the SNS Topic currently receiving events
3. Take Note the ARN of this SNS topic
4. Select the `Edit` button and scroll down to the `Access Policy` card
5. Add the statement shown below to the topic's `Access Policy`. Populate `<MasterAccountId>` with the 12-digit account ID where Panther is deployed. Populate `SNS-TOPIC-ARN` with the ARN you noted on step \#3:

```yaml
Sid: CrossAccountSubscription
Effect: Allow
Principal:
  AWS: arn:aws:iam::<MasterAccountId>:root
Action: sns:Subscribe,
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

Finally, create the subscription to the Panther Master Account's SQS Queue.

From the SNS Console, select the `Create subscription` button:

1. `Protocol`: `Amazon SQS`
2. `Endpoint`: `arn:aws:sns:<PantherRegion>:<MasterAccountId>:panther-notifications-topic`
3. Select the `Create subscription` button

## Log Processing Advanced Configurations

These are just two basic configurations to integrate with Panther Log Processing.

There are other variations and advanced configurations available for more complex use cases and considerations. For example, instead of using S3 event notifications for CloudTrail data you may have CloudTrail directly notify SNS of the new data.
