# Notifications Setup

{% hint style="info" %}
This page is for users with existing S3 bucket\(s\) configured to capture data such as CloudTrail, S3 Server Access logs, endpoint data, and more.
{% endhint %}

## Existing S3 Buckets

In the following steps, we will create an SNS Topic and SNS Subscription to notify Panther when new data is ready for processing in the S3 buckets:

1. Log into the AWS Console of the account that owns the S3 buckets that contain your logs
2. Select the AWS Region where your S3 buckets are located
3. Select **CloudFormation** AWS Service and click on **Create Stack**
4. Enter the following S3 URL `https://panther-public-cloudformation-templates.s3-us-west-2.amazonaws.com/panther-log-processing-notifications/latest/template.yml`
5. Fill the form with the appropriate information:
   1. `Stack name`: Give the stack a name of your choice, e.g. `panther-log-processing-notifications`
   2. `PantherAccountId` : The 12 digit AWS Account ID where Panther is deployed
   3. `PantherRegion`: The region where Panther is deployed
   4. `SnsTopicName`: The name for your SNS topic  
6. Click on **Next** and again **Next**. Click on **Create Stack**. This stack has one output named`SnsTopicArn`
7. Add [event notifications](https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html) to the S3 buckets intended for data ingestion so they will notify the SNS Topic

   1. This can be accomplished via the AWS Console by navigating to the AWS [S3 console](https://s3.console.aws.amazon.com/s3/home), selecting the relevant bucket\(s\), and then navigating to the `Properties` tab. From there, scroll down to the `Advanced settings` section to find the `Events` card, and configure a new event to send `All object create events` to the topic created above
   2. Alternatively, this can be accomplished via CloudFormation if the S3 buckets are being managed via CloudFormation. Simply add the following property to the relevant S3 bucket\(s\):

   ```yaml
   Resources:
     CloudTrailBucket:
       Type: AWS::S3::Bucket
       Properties:
         BucketName: my-cloudtrail-bucket
         NotificationConfiguration:
           TopicConfigurations:
             - Topic: SNS-TOPIC-ARN
               Event: s3:ObjectCreated:*
   ```

   ```javascript
   {
     "Resources": {
       "CloudTrailBucket": {
         "Type": "AWS::S3::Bucket",
         "Properties": {
           "BucketName": "my-cloudtrail-bucket",
           "NotificationConfiguration": {
             "TopicConfigurations": [
               "Topic": "SNS-TOPIC-ARN",
               "Event": "s3:ObjectCreated:*"
             ]
           }
         }
       }
     }
   }
   ```

## Existing S3 Buckets and SNS Topics

This setup is for users who already have an S3 bucket or buckets aggregating data, and SNS Topics receiving `All object create events` from those buckets. All you need to do in this case is create a subscription between your SNS topic and Panther's log processing SQS queue. These steps assume management is being done via the AWS Console, if management is preferred via CloudFormation \(or some other infrastructure management tool\) skip to step 5:

1. Log into the AWS Console for the account in which you are currently storing logs
2. Navigate to the [SNS topics](https://us-west-2.console.aws.amazon.com/sns/v3/home#/topics) dashboard and select the SNS Topic currently receiving events from the S3 buckets
3. Note the ARN of this SNS topic
4. Select the `Edit` button and scroll down to the `Access Policy` card
5. Add the statement shown below to the topic's `Access Policy`. Populate `PANTHER-AWS-ACCOUNT-ID` with the 12-digit account ID where Panther is deployed. Populate `SNS-TOPIC-ARN` with the ARN you noted on step \#3:

```yaml
Sid: CrossAccountSubscription
Effect: Allow
Principal:
  AWS: arn:aws:iam::PANTHER-AWS-ACCOUNT-ID:root
Action: sns:Subscribe,
Resource: SNS-TOPIC-ARN
```

```text
{
  "Sid": "CrossAccountSubscription",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::PANTHER-AWS-ACCOUNT-ID:root"
  },
  "Action": "sns:Subscribe",
  "Resource": "SNS-TOPIC-ARN"
}
```

Finally, create an SNS subscription for the Panther Master Account's SQS Queue. From the SNS Console, select the `Create subscription` button:

- In the `Protocol` dropdown select `Amazon SQS`
- In the `Endpoint` field enter `arn:aws:sqs:PANTHER-AWS-REGION:PANTHER-AWS-ACCOUNT-ID:panther-input-data-notifications`
- Select the `Create subscription` button

## Log Processing for Advanced Configurations

These are just two basic configurations to integrate with Panther Log Processing. There are other variations and advanced configuration options available for more complex use cases and considerations.

For example, instead of using S3 event notifications for CloudTrail data you may have CloudTrail directly notify SNS of the new data.
