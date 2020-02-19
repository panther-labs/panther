//nolint:lll
package processor

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	schemas "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
)

const (
	sampleConfirmation = `
{
	"Type": "SubscriptionConfirmation",
	"MessageId": "fed763a0-4d7b-45fd-81f3-55adf2fb1841",
	"Token": "REDACTED-c70f477b3ecc3b82cef61ec3dd5df4366666ed54f-REDACTED",
	"TopicArn": "arn:aws:sns:us-east-1:111111111111:PantherEvents",
	"Message": "You have chosen to subscribe to the topic arn:aws:sns:us-east-1:857418155548:PantherEvents.To confirm the subscription, visit the SubscribeURL included in this message.",
	"SubscribeURL": "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn:aws:sns:us-east-1:857418155548:PantherEvents&Token=REDACTED-c70f477b3ecc3b82cef61ec3dd5df4366666ed54f-REDACTED",
	"Timestamp": "2019-07-11T22:34:49.439Z",
	"SignatureVersion": "1",
	"Signature": "REDACTED-GZngNiNpGCIWSlhPZU3mLvGE8D072c4op2nf75uPz/qR6AP-REDACTED",
	"SigningCertURL": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-6aad65c2f9911b05cd53efda11f913f9.pem"
}`

	sampleUpdate = `
{
	"version": "0",
	"id": "89a4d1f0-9918-3d8f-65cd-4f2145d91255",
	"detail-type": "AWS API Call via CloudTrail",
	"source": "aws.s3",
	"account": "111111111111",
	"time": "2019-08-16T23:05:04Z",
	"region": "us-west-2",
	"resources": [],
	"detail": {
		"eventVersion": "1.05",
		"userIdentity": {
			"type": "AssumedRole",
			"principalId": "AROAIZAKJCWU7GMRGJX6E:austin_byers",
			"arn": "arn:aws:sts::111111111111:assumed-role/PantherDevAustinAdministrator/austin_byers",
			"accountId": "111111111111",
			"accessKeyId": "ASIARPM7LCOWYSBK3SXF",
			"sessionContext": {
				"attributes": {
					"mfaAuthenticated": "true",
					"creationDate": "2019-08-01T03:59:22Z"
				},
				"sessionIssuer": {
					"type": "Role",
					"principalId": "AROAIZAKJCWU7GMRGJX6E",
					"arn": "arn:aws:iam::111111111111:role/PantherDevAustinAdministrator",
					"accountId": "101802775469",
					"userName": "PantherDevAustinAdministrator"
				}
			}
		},
		"eventTime": "2019-08-01T04:41:47Z",
		"eventSource": "s3.amazonaws.com",
		"eventName": "PutBucketPublicAccessBlock",
		"awsRegion": "us-west-2",
		"sourceIPAddress": "136.25.4.99",
		"userAgent": "[S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.590 Linux/4.9.152-0.1.ac.221.79.329.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.212-b03 java/1.8.0_212 vendor/Oracle_Corporation]",
		"requestParameters": {
			"publicAccessBlock": [
				""
			],
			"PublicAccessBlockConfiguration": {
				"xmlns": "http://s3.amazonaws.com/doc/2006-03-01/",
				"RestrictPublicBuckets": true,
				"BlockPublicPolicy": false,
				"BlockPublicAcls": false,
				"IgnorePublicAcls": true
			},
			"bucketName": "austin-panther",
			"host": [
				"austin-panther.s3.us-west-2.amazonaws.com"
			]
		},
		"responseElements": null,
		"additionalEventData": {
			"SignatureVersion": "SigV4",
			"CipherSuite": "ECDHE-RSA-AES128-SHA",
			"AuthenticationMethod": "AuthHeader",
			"vpcEndpointId": "vpce-a0d039c9"
		},
		"requestID": "84135C596F3D9C7F",
		"eventID": "43258a7e-eef1-44ef-9aff-1e5b4cfd825d",
		"eventType": "AwsApiCall",
		"vpcEndpointId": "vpce-a0d039c9",
		"recipientAccountId": "111111111111"
	}
}
`
)

var (
	testContext = &lambdacontext.LambdaContext{AwsRequestID: "test-request-id"}
)

// Invalid sqs message is dropped and logged
func TestHandleInvalid(t *testing.T) {
	logs := mockLogger()
	resetAccountCache()

	mockLambda := &mockLambdaClient{}
	mockLambda.
		On("Invoke", getTestInvokeInput()).
		Return(getTestInvokeOutput(exampleIntegrations, 200), nil)
	lambdaClient = mockLambda

	batch := &events.SQSEvent{
		Records: []events.SQSMessage{
			{Body: `{this is " not even valid JSON:`},
		},
	}
	require.Nil(t, Handle(testContext, batch))
	t.Log(logs.AllUntimed())
	require.Equal(t, 1, len(logs.FilterField(zap.String("body",`{this is " not even valid JSON:`)).AllUntimed()))
	assert.Equal(t, logs.FilterField(zap.String("body",`{this is " not even valid JSON:`)).AllUntimed()[0].ContextMap()["error"].(string),
		"unexpected SNS message")
}

// Handle sns confirmation end-to-end
func TestHandleConfirmation(t *testing.T) {
	logs := mockLogger()
	resetAccountCache()

	mockLambda := &mockLambdaClient{}
	mockLambda.
		On("Invoke", getTestInvokeInput()).
		Return(getTestInvokeOutput(exampleIntegrations, 200), nil)
	lambdaClient = mockLambda

	mockSnsClient := &mockSns{}
	expectedInput := &sns.ConfirmSubscriptionInput{
		Token:    aws.String("REDACTED-c70f477b3ecc3b82cef61ec3dd5df4366666ed54f-REDACTED"),
		TopicArn: aws.String("arn:aws:sns:us-east-1:111111111111:PantherEvents"),
	}
	output := &sns.ConfirmSubscriptionOutput{
		SubscriptionArn: aws.String("arn:aws:sns:us-east-1:111111111111:PantherEvents:random-id")}
	mockSnsClient.On("ConfirmSubscription", expectedInput).Return(output, nil)
	snsClientBuilder = func(*string) (snsiface.SNSAPI, error) {
		return mockSnsClient, nil
	}

	batch := &events.SQSEvent{
		Records: []events.SQSMessage{
			{Body: sampleConfirmation},
		},
	}

	require.Nil(t, Handle(testContext, batch))
	assert.Equal(t, 1, len(logs.FilterMessage("processing SNS confirmation").AllUntimed()))
	require.Equal(t, 1, len(logs.FilterMessage("confirming sns subscription").AllUntimed()))
	assert.Equal(t, logs.FilterMessage("confirming sns subscription").AllUntimed()[0].ContextMap()["topicArn"].(string),
		*expectedInput.TopicArn)
	require.Equal(t, 1, len(logs.FilterMessage("sns subscription confirmed successfully").AllUntimed()))
	assert.Equal(t, logs.FilterMessage("sns subscription confirmed successfully").AllUntimed()[0].ContextMap()["subscriptionArn"].(string),
		*output.SubscriptionArn)
}

// Handle update end-to-end
func TestHandleUpdate(t *testing.T) {
	logs := mockLogger()
	resetAccountCache()

	mockLambda := &mockLambdaClient{}
	mockLambda.
		On("Invoke", getTestInvokeInput()).
		Return(getTestInvokeOutput(exampleIntegrations, 200), nil)
	lambdaClient = mockLambda

	queueURL = "poller-queue"
	mockSqsClient := &mockSqs{}
	expectedRequest := poller.ScanMsg{
		Entries: []*poller.ScanEntry{
			{
				AWSAccountID:     aws.String("111111111111"),
				IntegrationID:    aws.String("ebb4d69f-177b-4eff-a7a6-9251fdc72d21"),
				ResourceID:       aws.String("arn:aws:s3:::austin-panther"),
				ResourceType:     aws.String(schemas.S3BucketSchema),
				ScanAllResources: aws.Bool(false),
			},
		},
	}

	body, err := jsoniter.MarshalToString(&expectedRequest)
	require.NoError(t, err)
	expectedInput := &sqs.SendMessageBatchInput{
		Entries: []*sqs.SendMessageBatchRequestEntry{
			{
				Id:           aws.String("0"),
				MessageBody:  aws.String(body),
				DelaySeconds: aws.Int64(0),
			},
		},
		QueueUrl: aws.String("poller-queue"),
	}

	mockSqsClient.On("SendMessageBatch", expectedInput).Return(&sqs.SendMessageBatchOutput{}, nil)
	sqsClient = mockSqsClient

	wrappedUpdateMap := map[string]string{
		"Message":          sampleUpdate,
		"MessageId":        "d21fd010-797f-501b-9b33-862446980e00",
		"Signature":        "redacted",
		"SignatureVersion": "1",
		"SigningCertURL":   "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-6aad65c2f9911b05cd53efda11f913f9.pem",
		"Timestamp":        "2019-10-31T01:49:27.538Z",
		"TopicArn":         "arn:aws:sns:us-west-2:857418155548:PantherEvents",
		"Type":             "Notification",
		"UnsubscribeURL":   "https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:857418155548:PantherEvents:59e695d2-3f28-487d-a3e1-18a48441766c",
	}
	wrappedUpdate, err := jsoniter.MarshalToString(wrappedUpdateMap)
	require.NoError(t, err)

	batch := &events.SQSEvent{
		Records: []events.SQSMessage{
			{Body: sampleUpdate},
			{Body: wrappedUpdate}, // same resource - only one entry should be queued for scanning
		},
	}
	require.Nil(t, Handle(testContext, batch))
	mockSqsClient.AssertExpectations(t)

	expectedChange := &resourceChange{
		AwsAccountID:  "111111111111",
		EventName:     "PutBucketPublicAccessBlock",
		EventTime:     "2019-08-01T04:41:47Z",
		IntegrationID: "ebb4d69f-177b-4eff-a7a6-9251fdc72d21",
		ResourceID:    "arn:aws:s3:::austin-panther",
		ResourceType:  schemas.S3BucketSchema,
	}

	assert.Equal(t, 2, len(logs.FilterMessage("resource change required").AllUntimed()))
	for _, log := range logs.FilterMessage("resource change required").AllUntimed() {
		actualChange := log.ContextMap()["changeDetail"].(*resourceChange)
		assert.Equal(t, expectedChange, actualChange)
	}
	assert.Equal(t, 1, len(logs.FilterMessage("queueing resource scans").AllUntimed()))
	for _, log := range logs.FilterMessage("queueing resource scans").AllUntimed() {
		actualRequest := log.ContextMap()["updateRequest"].(*poller.ScanMsg)
		assert.Equal(t, &expectedRequest, actualRequest)
	}
	assert.Equal(t, 1, len(logs.FilterMessage("starting sqsbatch.SendMessageBatch").AllUntimed()))
	assert.Equal(t, 1, len(logs.FilterMessage("invoking sqs.SendMessageBatch").AllUntimed()))
}
