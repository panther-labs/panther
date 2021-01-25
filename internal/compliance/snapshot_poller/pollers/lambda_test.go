package pollers

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
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
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	lru "github.com/hashicorp/golang-lru"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	resourcesapi "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	pollers "github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var testIntegrationID = "0aab70c6-da66-4bb9-a83c-bbe8f5717fde"

func TestBatchResources(t *testing.T) {
	var testResources []resourcesapi.AddResourceEntry
	for i := 0; i < 1100; i++ {
		testResources = append(testResources, resourcesapi.AddResourceEntry{
			Attributes:      &awsmodels.CloudTrailMeta{},
			ID:              "arn:aws:cloudtrail:region:account-id:trail/trailname",
			IntegrationID:   testIntegrationID,
			IntegrationType: "aws",
			Type:            "AWS.CloudTrail",
		})
	}

	testBatches := batchResources(testResources)
	require.NotEmpty(t, testBatches)
	assert.Len(t, testBatches, 3)
	assert.Len(t, testBatches[0], 500)
	assert.Len(t, testBatches[1], 500)
	assert.Len(t, testBatches[2], 100)
}

func testContext() context.Context {
	return lambdacontext.NewContext(
		context.Background(),
		&lambdacontext.LambdaContext{
			InvokedFunctionArn: "arn:aws:lambda:us-west-2:123456789123:function:snapshot-pollers:live",
			AwsRequestID:       "ad32d898-2a37-484d-9c50-3708c8fbc7d6",
		},
	)
}

func mockTimeFunc() time.Time {
	return time.Time{}
}

// Replace global logger with an in-memory observer for tests.
func mockLogger(level zapcore.Level) *observer.ObservedLogs {
	core, mockLog := observer.New(level)
	zap.ReplaceGlobals(zap.New(core))
	return mockLog
}

// Skip global logger creation
func setupTestLogger(ctx context.Context, _ map[string]interface{}) *lambdacontext.LambdaContext {
	lc, ok := lambdacontext.FromContext(ctx)
	if !ok {
		panic("lambdacontext.FromContext failed")
	}
	return lc
}

func TestHandlerNonExistentIntegration(t *testing.T) {
	loggerSetupFunc = setupTestLogger
	logger := mockLogger(zapcore.InfoLevel)

	pollers.RateLimitTracker, _ = lru.NewARC(10)
	mockResourceClient := &gatewayapi.MockClient{}
	apiClient = mockResourceClient
	pollers.AuditRoleName = "TestAuditRole"

	testIntegrations := &pollermodels.ScanMsg{
		Entries: []*pollermodels.ScanEntry{
			{
				AWSAccountID:  aws.String("123456789012"),
				IntegrationID: &testIntegrationID,
				ResourceID:    aws.String("arn:aws:s3:::test"),
				ResourceType:  aws.String("AWS.NonExistentResource.Type"),
			},
		},
	}
	testIntegrationStr, err := jsoniter.MarshalToString(testIntegrations)
	require.NoError(t, err)

	sampleEvent := events.SQSEvent{
		Records: []events.SQSMessage{
			{
				AWSRegion:     "us-west-2",
				MessageId:     "702a0aba-ab1f-11e8-b09c-f218981400a1",
				ReceiptHandle: "AQEBCki01vLygW9L6Xq1hcSNR90swZdtgZHP1N5hEU1Dt22p66gQFxKEsVo7ObxpC+b/",
				Body:          testIntegrationStr,
				Md5OfBody:     "d3673b20e6c009a81c73961b798f838a",
			},
		},
	}
	require.NoError(t, Handle(testContext(), sampleEvent))

	mockResourceClient.AssertNumberOfCalls(t, "Invoke", 0)
	expected := []observer.LoggedEntry{
		{
			Entry:   zapcore.Entry{Level: zapcore.ErrorLevel, Message: "unable to perform scan of specified resource type"},
			Context: []zapcore.Field{zap.String("resourceType", "AWS.NonExistentResource.Type")},
		},
	}
	logs := logger.AllUntimed()
	require.Len(t, logs, 2)
	assert.Equal(t, expected, logs[:1]) // throw out last oplog msg
}

func TestPollSourceNotEnabled(t *testing.T) {
	loggerSetupFunc = setupTestLogger
	logger := mockLogger(zapcore.InfoLevel)
	mockResourceClient := &gatewayapi.MockClient{}
	apiClient = mockResourceClient
	pollers.AuditRoleName = "TestAuditRole"

	testIntegrations := &pollermodels.ScanMsg{
		Entries: []*pollermodels.ScanEntry{
			{
				AWSAccountID:  aws.String("123456789012"),
				IntegrationID: &testIntegrationID,
				Region:        aws.String("us-west-2"),
				ResourceType:  aws.String(awsmodels.KmsKeySchema),
				Enabled:       aws.Bool(false),
			},
		},
	}
	testIntegrationStr, err := jsoniter.MarshalToString(testIntegrations)
	require.NoError(t, err)

	sampleEvent := events.SQSEvent{
		Records: []events.SQSMessage{
			{
				AWSRegion:     "us-west-2",
				MessageId:     "702a0aba-ab1f-11e8-b09c-f218981400a1",
				ReceiptHandle: "AQEBCki01vLygW9L6Xq1hcSNR90swZdtgZHP1N5hEU1Dt22p66gQFxKEsVo7ObxpC+b/",
				Body:          testIntegrationStr,
				Md5OfBody:     "d3673b20e6c009a81c73961b798f838a",
			},
		},
	}
	require.NoError(t, Handle(testContext(), sampleEvent))

	mockResourceClient.AssertExpectations(t)
	expected := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{Level: zapcore.InfoLevel, Message: "source integration disabled"},
			Context: []zapcore.Field{
				zap.String("integration id", "0aab70c6-da66-4bb9-a83c-bbe8f5717fde"),
			},
		},
	}
	logs := logger.AllUntimed()
	require.Len(t, logs, 2)
	assert.Equal(t, expected, logs[:1])
}

func TestPollRegionIgnored(t *testing.T) {
	loggerSetupFunc = setupTestLogger
	logger := mockLogger(zapcore.InfoLevel)
	mockResourceClient := &gatewayapi.MockClient{}
	apiClient = mockResourceClient
	pollers.AuditRoleName = "TestAuditRole"

	testIntegrations := &pollermodels.ScanMsg{
		Entries: []*pollermodels.ScanEntry{
			{
				AWSAccountID:     aws.String("123456789012"),
				IntegrationID:    &testIntegrationID,
				Region:           aws.String("us-west-2"),
				ResourceType:     aws.String(awsmodels.KmsKeySchema),
				RegionIgnoreList: []string{"us-west-2"},
			},
		},
	}
	testIntegrationStr, err := jsoniter.MarshalToString(testIntegrations)
	require.NoError(t, err)

	sampleEvent := events.SQSEvent{
		Records: []events.SQSMessage{
			{
				AWSRegion:     "us-west-2",
				MessageId:     "702a0aba-ab1f-11e8-b09c-f218981400a1",
				ReceiptHandle: "AQEBCki01vLygW9L6Xq1hcSNR90swZdtgZHP1N5hEU1Dt22p66gQFxKEsVo7ObxpC+b/",
				Body:          testIntegrationStr,
				Md5OfBody:     "d3673b20e6c009a81c73961b798f838a",
			},
		},
	}

	require.NoError(t, Handle(testContext(), sampleEvent))

	mockResourceClient.AssertExpectations(t)
	expected := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{Level: zapcore.InfoLevel, Message: "processing single region service scan"},
			Context: []zapcore.Field{
				zap.String("region", "us-west-2"),
				zap.String("resourceType", "AWS.KMS.Key"),
			},
		},
		{
			Entry: zapcore.Entry{Level: zapcore.InfoLevel, Message: "matched ignoreList region - skipping scan"},
			Context: []zapcore.Field{
				zap.String("region", "us-west-2"),
			},
		},
	}
	logs := logger.AllUntimed()
	require.Len(t, logs, 3)
	assert.Equal(t, expected, logs[:2]) // throw out last oplog msg
}

func TestPollResourceTypeIgnored(t *testing.T) {
	loggerSetupFunc = setupTestLogger
	logger := mockLogger(zapcore.InfoLevel)
	mockResourceClient := &gatewayapi.MockClient{}
	apiClient = mockResourceClient
	pollers.AuditRoleName = "TestAuditRole"

	testIntegrations := &pollermodels.ScanMsg{
		Entries: []*pollermodels.ScanEntry{
			{
				AWSAccountID:           aws.String("123456789012"),
				IntegrationID:          &testIntegrationID,
				Region:                 aws.String("us-west-2"),
				ResourceType:           aws.String(awsmodels.KmsKeySchema),
				ResourceTypeIgnoreList: []string{"AWS.KMS.Key"},
			},
		},
	}
	testIntegrationStr, err := jsoniter.MarshalToString(testIntegrations)
	require.NoError(t, err)

	sampleEvent := events.SQSEvent{
		Records: []events.SQSMessage{
			{
				AWSRegion:     "us-west-2",
				MessageId:     "702a0aba-ab1f-11e8-b09c-f218981400a1",
				ReceiptHandle: "AQEBCki01vLygW9L6Xq1hcSNR90swZdtgZHP1N5hEU1Dt22p66gQFxKEsVo7ObxpC+b/",
				Body:          testIntegrationStr,
				Md5OfBody:     "d3673b20e6c009a81c73961b798f838a",
			},
		},
	}

	require.NoError(t, Handle(testContext(), sampleEvent))

	mockResourceClient.AssertExpectations(t)
	expected := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{Level: zapcore.InfoLevel, Message: "resource type filtered"},
			Context: []zapcore.Field{
				zap.String("resource type", "AWS.KMS.Key"),
			},
		},
	}
	logs := logger.AllUntimed()
	require.Len(t, logs, 2)
	assert.Equal(t, expected, logs[:1]) // throw out last oplog msg
}

// End-to-end unit test
func TestHandler(t *testing.T) {
	loggerSetupFunc = setupTestLogger
	logger := mockLogger(zapcore.InfoLevel)
	mockResourceClient := &gatewayapi.MockClient{}
	apiClient = mockResourceClient
	pollers.AuditRoleName = "TestAuditRole"

	testIntegrations := &pollermodels.ScanMsg{
		Entries: []*pollermodels.ScanEntry{
			{
				AWSAccountID:  aws.String("123456789012"),
				IntegrationID: &testIntegrationID,
				Region:        aws.String("us-west-2"),
				ResourceType:  aws.String(awsmodels.KmsKeySchema),
			},
		},
	}
	testIntegrationStr, err := jsoniter.MarshalToString(testIntegrations)
	require.NoError(t, err)

	awstest.MockKmsForSetup = awstest.BuildMockKmsSvcAll()

	mockStsClient := &awstest.MockSTS{}
	mockStsClient.
		On("GetCallerIdentity", &sts.GetCallerIdentityInput{}).
		Return(
			&sts.GetCallerIdentityOutput{
				Account: aws.String("123456789012"),
				Arn:     aws.String("arn:aws:iam::123456789012:role/PantherAuditRole"),
				UserId:  aws.String("mockUserId"),
			},
			nil,
		)
	awstest.MockSTSForSetup = mockStsClient

	pollers.KmsClientFunc = awstest.SetupMockKms
	pollers.AssumeRoleFunc = awstest.AssumeRoleMock
	pollers.VerifyAssumedCredsFunc = func(sess *session.Session, region string) error {
		return nil
	}
	// Provide stub poller session
	pollers.SnapshotPollerSession = &session.Session{}

	utils.TimeNowFunc = mockTimeFunc

	sampleEvent := events.SQSEvent{
		Records: []events.SQSMessage{
			{
				AWSRegion:     "us-west-2",
				MessageId:     "702a0aba-ab1f-11e8-b09c-f218981400a1",
				ReceiptHandle: "AQEBCki01vLygW9L6Xq1hcSNR90swZdtgZHP1N5hEU1Dt22p66gQFxKEsVo7ObxpC+b/",
				Body:          testIntegrationStr,
				Md5OfBody:     "d3673b20e6c009a81c73961b798f838a",
			},
		},
	}

	lambdaInput := &resourcesapi.LambdaInput{
		AddResources: &resourcesapi.AddResourcesInput{
			Resources: []resourcesapi.AddResourceEntry{
				{
					Attributes: &awsmodels.KmsKey{
						GenericAWSResource: awsmodels.GenericAWSResource{
							AccountID: aws.String("123456789012"),
							Region:    aws.String("us-west-2"),
							ARN:       aws.String("arn:aws:kms:us-west-2:111111111111:key/188c57ed-b28a-4c0e-9821-f4940d15cb0a"),
							ID:        aws.String("188c57ed-b28a-4c0e-9821-f4940d15cb0a"),
						},
						GenericResource: awsmodels.GenericResource{
							ResourceID:   aws.String("arn:aws:kms:us-west-2:111111111111:key/188c57ed-b28a-4c0e-9821-f4940d15cb0a"),
							ResourceType: aws.String(awsmodels.KmsKeySchema),
							TimeCreated:  &awstest.ExampleTime,
						},
						Description:        aws.String("Encryption key for panther-snapshot-queue data"),
						Enabled:            aws.Bool(true),
						KeyManager:         aws.String("CUSTOMER"),
						KeyState:           aws.String("Enabled"),
						KeyUsage:           aws.String("ENCRYPT_DECRYPT"),
						Origin:             aws.String("AWS_KMS"),
						KeyRotationEnabled: aws.Bool(true),
						Policy:             awstest.ExampleGetKeyPolicyOutput.Policy,
					},
					ID:              "arn:aws:kms:us-west-2:111111111111:key/188c57ed-b28a-4c0e-9821-f4940d15cb0a",
					IntegrationID:   "0aab70c6-da66-4bb9-a83c-bbe8f5717fde",
					IntegrationType: "aws",
					Type:            awsmodels.KmsKeySchema,
				},
				{
					Attributes: &awsmodels.KmsKey{
						GenericAWSResource: awsmodels.GenericAWSResource{
							AccountID: aws.String("123456789012"),
							Region:    aws.String("us-west-2"),
							ARN:       aws.String("arn:aws:kms:us-west-2:111111111111:key/d15a1e37-3ef7-4882-9be5-ef3a024114db"),
							ID:        aws.String("d15a1e37-3ef7-4882-9be5-ef3a024114db"),
						},
						GenericResource: awsmodels.GenericResource{
							ResourceID:   aws.String("arn:aws:kms:us-west-2:111111111111:key/d15a1e37-3ef7-4882-9be5-ef3a024114db"),
							ResourceType: aws.String(awsmodels.KmsKeySchema),
							TimeCreated:  &awstest.ExampleTime,
						},
						Description:        aws.String("Encryption key for panther-snapshot-queue data"),
						Enabled:            aws.Bool(true),
						KeyManager:         aws.String("CUSTOMER"),
						KeyState:           aws.String("Enabled"),
						KeyUsage:           aws.String("ENCRYPT_DECRYPT"),
						Origin:             aws.String("AWS_KMS"),
						KeyRotationEnabled: aws.Bool(true),
						Policy:             awstest.ExampleGetKeyPolicyOutput.Policy,
					},
					ID:              "arn:aws:kms:us-west-2:111111111111:key/d15a1e37-3ef7-4882-9be5-ef3a024114db",
					IntegrationID:   "0aab70c6-da66-4bb9-a83c-bbe8f5717fde",
					IntegrationType: "aws",
					Type:            awsmodels.KmsKeySchema,
				},
			},
		},
	}
	mockResourceClient.On("Invoke", lambdaInput, nil).Return(http.StatusOK, nil, nil)

	require.NoError(t, Handle(testContext(), sampleEvent))

	mockResourceClient.AssertExpectations(t)
	expected := []observer.LoggedEntry{
		{
			Entry: zapcore.Entry{Level: zapcore.InfoLevel, Message: "processing single region service scan"},
			Context: []zapcore.Field{
				zap.String("region", "us-west-2"),
				zap.String("resourceType", "AWS.KMS.Key"),
			},
		},
		{
			Entry: zapcore.Entry{Level: zapcore.InfoLevel, Message: "resources generated"},
			Context: []zapcore.Field{
				zap.Int64("numResources", 2),
				zap.String("resourcePoller", "KMSKey"),
			},
		},
	}
	logs := logger.AllUntimed()
	require.Len(t, logs, 3)
	assert.Equal(t, expected, logs[:2]) // throw out last oplog msg
}
