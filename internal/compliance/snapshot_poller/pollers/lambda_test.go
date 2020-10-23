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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	resourcesapi "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

var testIntegrationID = "0aab70c6-da66-4bb9-a83c-bbe8f5717fde"

func TestBatchResources(t *testing.T) {
	var testResources []*resourcesapi.AddResourceEntry
	for i := 0; i < 1100; i++ {
		testResources = append(testResources, &resourcesapi.AddResourceEntry{
			Attributes:      &awsmodels.CloudTrailMeta{},
			ID:              "arn:aws:cloudtrail:region:account-id:trail/trailname",
			IntegrationID:   resourcesapi.IntegrationID(testIntegrationID),
			IntegrationType: resourcesapi.IntegrationTypeAws,
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

/*
TODO - skipping until resources-api mock is in place

func testContext() context.Context {
	return lambdacontext.NewContext(
		context.Background(),
		&lambdacontext.LambdaContext{
			InvokedFunctionArn: "arn:aws:lambda:us-west-2:123456789123:function:snapshot-pollers:live",
			AwsRequestID:       "ad32d898-2a37-484d-9c50-3708c8fbc7d6",
		},
	)
}

var (
	mockTime          = time.Time{}
)

func mockTimeFunc() time.Time {
	return mockTime
}

func TestHandlerNonExistentIntegration(t *testing.T) {
	t.Skip("skipping until resources-api mock is in place")
	testIntegrations := &pollermodels.ScanMsg{
		Entries: []*pollermodels.ScanEntry{
			{
				AWSAccountID:     aws.String("123456789012"),
				IntegrationID:    &testIntegrationID,
				ResourceID:       aws.String("arn:aws:s3:::test"),
				ResourceType:     aws.String("AWS.NonExistentResource.Type"),
				ScanAllResources: aws.Bool(false),
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
}

func TestHandler(t *testing.T) {
	t.Skip("skipping until resources-api mock is in place")
	testIntegrations := &pollermodels.ScanMsg{
		Entries: []*pollermodels.ScanEntry{
			{
				AWSAccountID:     aws.String("123456789012"),
				IntegrationID:    &testIntegrationID,
				ScanAllResources: aws.Bool(true),
			},
		},
	}
	testIntegrationStr, err := jsoniter.MarshalToString(testIntegrations)
	require.NoError(t, err)

	// Setup ACM client and function mocks
	awstest.MockAcmForSetup = awstest.BuildMockAcmSvcAll()

	// Setup CloudFormation client and function mocks
	awstest.MockCloudFormationForSetup = awstest.BuildMockCloudFormationSvcAll()

	// Setup CloudWatchLogs client and function mocks
	awstest.MockCloudWatchLogsForSetup = awstest.BuildMockCloudWatchLogsSvcAll()

	// Setup CloudTrail client and function mocks
	awstest.MockCloudTrailForSetup = awstest.BuildMockCloudTrailSvcAll()

	// Setup IAM client and function mocks
	awstest.MockIAMForSetup = awstest.BuildMockIAMSvcAll()

	// Setup Lambda client and function mocks
	awstest.MockLambdaForSetup = awstest.BuildMockLambdaSvcAll()

	// Setup S3 client and function mocks
	awstest.MockS3ForSetup = awstest.BuildMockS3SvcAll()

	// Setup EC2 client and function mocks
	awstest.MockEC2ForSetup = awstest.BuildMockEC2SvcAll()

	// Setup ECS client and function mocks
	awstest.MockEcsForSetup = awstest.BuildMockEcsSvcAll()

	// Setup KMS client and function mocks
	awstest.MockKmsForSetup = awstest.BuildMockKmsSvcAll()

	// Setup ConfigService client with mock functions
	awstest.MockConfigServiceForSetup = awstest.BuildMockConfigServiceSvcAll()

	// Setup ELBV2 client and function mocks
	awstest.MockElbv2ForSetup = awstest.BuildMockElbv2SvcAll()

	// Setup WAF client and function mocks
	awstest.MockWafForSetup = awstest.BuildMockWafSvcAll()

	// Setup WAF Regional client and function mocks
	awstest.MockWafRegionalForSetup = awstest.BuildMockWafRegionalSvcAll()

	// Setup GuardDuty client and function mocks
	awstest.MockGuardDutyForSetup = awstest.BuildMockGuardDutySvcAll()

	// Setup DynamoDB client and function mocks
	awstest.MockDynamoDBForSetup = awstest.BuildMockDynamoDBSvcAll()

	// Setup DynamoDB client and function mocks
	awstest.MockApplicationAutoScalingForSetup = awstest.BuildMockApplicationAutoScalingSvcAll()

	// Setup RDS client and function mocks
	awstest.MockRdsForSetup = awstest.BuildMockRdsSvcAll()

	// Setup Redshift client and function mocks
	awstest.MockRedshiftForSetup = awstest.BuildMockRedshiftSvcAll()

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

	awspollers.AcmClientFunc = awstest.SetupMockAcm
	awspollers.ApplicationAutoScalingClientFunc = awstest.SetupMockApplicationAutoScaling
	awspollers.CloudTrailClientFunc = awstest.SetupMockCloudTrail
	awspollers.CloudWatchLogsClientFunc = awstest.SetupMockCloudWatchLogs
	awspollers.CloudFormationClientFunc = awstest.SetupMockCloudFormation
	awspollers.ConfigServiceClientFunc = awstest.SetupMockConfigService
	awspollers.DynamoDBClientFunc = awstest.SetupMockDynamoDB
	awspollers.EC2ClientFunc = awstest.SetupMockEC2
	awspollers.EcsClientFunc = awstest.SetupMockEcs
	awspollers.Elbv2ClientFunc = awstest.SetupMockElbv2
	awspollers.GuardDutyClientFunc = awstest.SetupMockGuardDuty
	awspollers.IAMClientFunc = awstest.SetupMockIAM
	awspollers.KmsClientFunc = awstest.SetupMockKms
	awspollers.LambdaClientFunc = awstest.SetupMockLambda
	awspollers.RDSClientFunc = awstest.SetupMockRds
	awspollers.RedshiftClientFunc = awstest.SetupMockRedshift
	awspollers.S3ClientFunc = awstest.SetupMockS3
	awspollers.WafClientFunc = awstest.SetupMockWaf
	awspollers.WafRegionalClientFunc = awstest.SetupMockWafRegional

	awspollers.assumeRoleFunc = awstest.AssumeRoleMock
	awspollers.assumeRoleProviderFunc = awstest.STSAssumeRoleProviderMock

	// Time mock
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

	require.NoError(t, Handle(testContext(), sampleEvent))
}

*/
