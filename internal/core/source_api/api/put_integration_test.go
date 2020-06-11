package api

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
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/panther-labs/panther/api/lambda/source/models"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	awspoller "github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/internal/core/source_api/ddb/modelstest"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/testutils"
)

func generateMockSQSBatchInputOutput(integration models.SourceIntegrationMetadata) (
	*sqs.SendMessageBatchInput, *sqs.SendMessageBatchOutput, error) {

	// Setup input/output
	var sqsEntries []*sqs.SendMessageBatchRequestEntry
	var err error
	in := &sqs.SendMessageBatchInput{
		QueueUrl: aws.String("test-url"),
	}
	out := &sqs.SendMessageBatchOutput{
		Successful: []*sqs.SendMessageBatchResultEntry{
			{
				Id:               integration.IntegrationID,
				MessageId:        integration.IntegrationID,
				MD5OfMessageBody: aws.String("f6255bb01c648fe967714d52a89e8e9c"),
			},
		},
	}

	// Generate all messages for scans
	for resourceType := range awspoller.ServicePollers {
		scanMsg := &pollermodels.ScanMsg{
			Entries: []*pollermodels.ScanEntry{
				{
					AWSAccountID:  integration.AWSAccountID,
					IntegrationID: integration.IntegrationID,
					ResourceType:  aws.String(resourceType),
				},
			},
		}

		var messageBodyBytes []byte
		messageBodyBytes, err = jsoniter.Marshal(scanMsg)
		if err != nil {
			break
		}

		sqsEntries = append(sqsEntries, &sqs.SendMessageBatchRequestEntry{
			Id:          integration.IntegrationID,
			MessageBody: aws.String(string(messageBodyBytes)),
		})
	}

	in.Entries = sqsEntries
	return in, out, err
}

// Unit Tests

func TestAddToSnapshotQueue(t *testing.T) {
	env.SnapshotPollersQueueURL = "test-url"
	testIntegration := models.SourceIntegrationMetadata{
		AWSAccountID:     aws.String(testAccountID),
		CreatedAtTime:    aws.Time(time.Time{}),
		CreatedBy:        aws.String("Bobert"),
		IntegrationID:    aws.String(testIntegrationID),
		IntegrationLabel: aws.String("BobertTest"),
		IntegrationType:  aws.String("aws-scan"),
		ScanIntervalMins: aws.Int(60),
	}

	sqsIn, sqsOut, err := generateMockSQSBatchInputOutput(testIntegration)
	require.NoError(t, err)

	mockSQS := &testutils.SqsMock{}
	// It's non trivial to mock when the order of a slice is not promised
	mockSQS.On("SendMessageBatch", mock.Anything).Return(sqsOut, nil)
	sqsClient = mockSQS

	err = apiTest.FullScan(&models.FullScanInput{Integrations: []*models.SourceIntegrationMetadata{&testIntegration}})

	require.NoError(t, err)
	// Check that there is one message per service
	assert.Len(t, sqsIn.Entries, len(awspoller.ServicePollers))
	mockSQS.AssertExpectations(t)
}

func TestPutCloudSecIntegration(t *testing.T) {
	mockSQS := &testutils.SqsMock{}
	mockSQS.On("SendMessageBatch", mock.Anything).Return(&sqs.SendMessageBatchOutput{}, nil) // count is hard to get due to batching
	sqsClient = mockSQS
	dynamoClient = &ddb.DDB{Client: &modelstest.MockDDBClient{TestErr: false}, TableName: "test"}
	evaluateIntegrationFunc = func(_ API, _ *models.CheckIntegrationInput) (string, bool, error) { return "", true, nil }

	out, err := apiTest.PutIntegration(&models.PutIntegrationInput{
		PutIntegrationSettings: models.PutIntegrationSettings{
			AWSAccountID:     aws.String(testAccountID),
			IntegrationLabel: aws.String(testIntegrationLabel),
			IntegrationType:  aws.String(models.IntegrationTypeAWSScan),
			ScanIntervalMins: aws.Int(60),
			UserID:           aws.String(testUserID),
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, out)
	mockSQS.AssertExpectations(t)
}

func TestPutLogIntegrationExists(t *testing.T) {
	evaluateIntegrationFunc = func(_ API, _ *models.CheckIntegrationInput) (string, bool, error) { return "", true, nil }

	dynamoClient = &ddb.DDB{
		Client: &modelstest.MockDDBClient{
			MockScanAttributes: []map[string]*dynamodb.AttributeValue{
				{
					"awsAccountId":     {S: aws.String(testAccountID)},
					"integrationType":  {S: aws.String(models.IntegrationTypeAWS3)},
					"integrationlabel": {S: aws.String(testIntegrationLabel)},
				},
			},
			TestErr: false,
		},
		TableName: "test",
	}

	out, err := apiTest.PutIntegration(&models.PutIntegrationInput{
		PutIntegrationSettings: models.PutIntegrationSettings{
			AWSAccountID:     aws.String(testAccountID),
			IntegrationLabel: aws.String(testIntegrationLabel),
			IntegrationType:  aws.String(models.IntegrationTypeAWS3),
			ScanIntervalMins: aws.Int(60),
			UserID:           aws.String(testUserID),
		},
	})
	require.Error(t, err)
	require.Empty(t, out)
	assert.Equal(t, "Log source for account 123456789012 with label ProdAWS already onboarded", err.Error())
}

func TestPutCloudSecIntegrationExists(t *testing.T) {
	evaluateIntegrationFunc = func(_ API, _ *models.CheckIntegrationInput) (string, bool, error) { return "", true, nil }

	dynamoClient = &ddb.DDB{
		Client: &modelstest.MockDDBClient{
			MockScanAttributes: []map[string]*dynamodb.AttributeValue{
				{
					"awsAccountId":     {S: aws.String(testAccountID)},
					"integrationType":  {S: aws.String(models.IntegrationTypeAWSScan)},
					"integrationlabel": {S: aws.String(testIntegrationLabel)},
				},
			},
			TestErr: false,
		},
		TableName: "test",
	}

	out, err := apiTest.PutIntegration(&models.PutIntegrationInput{
		PutIntegrationSettings: models.PutIntegrationSettings{
			AWSAccountID:     aws.String(testAccountID),
			IntegrationLabel: aws.String(testIntegrationLabel),
			IntegrationType:  aws.String(models.IntegrationTypeAWSScan),
			ScanIntervalMins: aws.Int(60),
			UserID:           aws.String(testUserID),
		},
	})
	require.Error(t, err)
	require.Empty(t, out)
	assert.Equal(t, "Source account 123456789012 already onboarded", err.Error())
}

func TestPutIntegrationValidInput(t *testing.T) {
	validator, err := models.Validator()
	require.NoError(t, err)
	assert.NoError(t, validator.Struct(&models.PutIntegrationInput{
		PutIntegrationSettings: models.PutIntegrationSettings{
			AWSAccountID:     aws.String(testAccountID),
			IntegrationLabel: aws.String(testIntegrationLabel),
			IntegrationType:  aws.String(models.IntegrationTypeAWSScan),
			ScanIntervalMins: aws.Int(60),
			UserID:           aws.String(testUserID),
		},
	}))
}

func TestPutIntegrationInvalidInput(t *testing.T) {
	validator, err := models.Validator()
	require.NoError(t, err)
	assert.Error(t, validator.Struct(&models.PutIntegrationInput{
		PutIntegrationSettings: models.PutIntegrationSettings{
			AWSAccountID:     aws.String(testAccountID),
			IntegrationLabel: aws.String(testIntegrationLabel),
			IntegrationType:  aws.String("type doesn't exist"),
			ScanIntervalMins: aws.Int(60),
			UserID:           aws.String(testUserID),
		},
	}))
}

func TestPutIntegrationDatabaseError(t *testing.T) {
	evaluateIntegrationFunc = func(_ API, _ *models.CheckIntegrationInput) (string, bool, error) { return "", true, nil }

	in := &models.PutIntegrationInput{
		PutIntegrationSettings: models.PutIntegrationSettings{
			AWSAccountID:     aws.String(testAccountID),
			IntegrationLabel: aws.String(testIntegrationLabel),
			IntegrationType:  aws.String(models.IntegrationTypeAWSScan),
			UserID:           aws.String(testUserID),
		},
	}
	dynamoClient = &ddb.DDB{
		Client: &modelstest.MockDDBClient{
			TestErr: true,
		},
		TableName: "test",
	}

	out, err := apiTest.PutIntegration(in)
	assert.Error(t, err)
	assert.Empty(t, out)
	assert.Equal(t, "Failed to add source. Please try again later", err.Error())
}

func TestPutIntegrationSQSErrorRecoveryFails(t *testing.T) {
	evaluateIntegrationFunc = func(_ API, _ *models.CheckIntegrationInput) (string, bool, error) { return "", true, nil }

	// Used to capture logs for unit testing purposes
	core, recordedLogs := observer.New(zapcore.ErrorLevel)
	zap.ReplaceGlobals(zap.New(core))

	in := &models.PutIntegrationInput{
		PutIntegrationSettings: models.PutIntegrationSettings{
			AWSAccountID:     aws.String(testAccountID),
			IntegrationLabel: aws.String(testIntegrationLabel),
			IntegrationType:  aws.String(models.IntegrationTypeAWS3),
			ScanIntervalMins: aws.Int(60),
			UserID:           aws.String(testUserID),
			LogTypes:         aws.StringSlice([]string{"AWS.VPCFlow"}),
		},
	}
	dynamoClient = &ddb.DDB{
		Client: &modelstest.MockDDBClient{
			TestErr: false,
		},
		TableName: "test",
	}

	mockSQS := &testutils.SqsMock{}
	sqsClient = mockSQS
	mockGlue := &testutils.GlueMock{}
	glueClient = mockGlue

	mockSQS.On("GetQueueAttributes", mock.Anything).Return(&sqs.GetQueueAttributesOutput{
		Attributes: generateQueueAttributeOutput(t, []string{}),
	}, nil).Once() // set
	mockSQS.On("SetQueueAttributes", mock.Anything).Return(&sqs.SetQueueAttributesOutput{},
		nil).Once() // set

	// fail the glue call to trigger the role back of permissions
	mockGlue.On("CreateTable", mock.Anything).Return(&glue.CreateTableOutput{}, errors.New("error")).Once()

	mockSQS.On("GetQueueAttributes", mock.Anything).Return(&sqs.GetQueueAttributesOutput{
		Attributes: generateQueueAttributeOutput(t, []string{testAccountID}),
	}, nil).Once() // unset
	mockSQS.On("SetQueueAttributes", mock.Anything).Return(&sqs.SetQueueAttributesOutput{},
		errors.New("error")).Once() // unset fails

	out, err := apiTest.PutIntegration(in)
	require.Error(t, err)
	require.Empty(t, out)

	errorLog := recordedLogs.FilterMessage("failed to remove SQS permission for integration." +
		" SQS queue has additional permissions that have to be removed manually")
	require.NotEmpty(t, errorLog.All())
	mockSQS.AssertExpectations(t)
}

func TestPutLogIntegrationUpdateSqsQueuePermissions(t *testing.T) {
	dynamoClient = &ddb.DDB{Client: &modelstest.MockDDBClient{TestErr: false}, TableName: "test"}
	mockSQS := &testutils.SqsMock{}
	sqsClient = mockSQS
	mockGlue := &testutils.GlueMock{}
	glueClient = mockGlue
	mockAthena := &testutils.AthenaMock{}
	athenaClient = mockAthena
	env.LogProcessorQueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/testqueue"
	evaluateIntegrationFunc = func(_ API, _ *models.CheckIntegrationInput) (string, bool, error) { return "", true, nil }

	expectedGetQueueAttributesInput := &sqs.GetQueueAttributesInput{
		AttributeNames: aws.StringSlice([]string{"Policy"}),
		QueueUrl:       aws.String(env.LogProcessorQueueURL),
	}
	alreadyExistingAttributes := generateQueueAttributeOutput(t, []string{})
	mockSQS.On("GetQueueAttributes", expectedGetQueueAttributesInput).
		Return(&sqs.GetQueueAttributesOutput{Attributes: alreadyExistingAttributes}, nil).Once()
	expectedAttributes := generateQueueAttributeOutput(t, []string{testAccountID})
	expectedSetAttributes := &sqs.SetQueueAttributesInput{
		Attributes: expectedAttributes,
		QueueUrl:   aws.String(env.LogProcessorQueueURL),
	}
	mockSQS.On("SetQueueAttributes", expectedSetAttributes).Return(&sqs.SetQueueAttributesOutput{}, nil).Once()

	// create the tables
	mockGlue.On("CreateTable", mock.Anything).Return(&glue.CreateTableOutput{}, nil).Twice()
	// create/replace the view
	mockGlue.On("GetTable", mock.Anything).Return(&glue.GetTableOutput{}, nil).Times(len(registry.AvailableTables()))
	mockAthena.On("StartQueryExecution", mock.Anything).Return(&athena.StartQueryExecutionOutput{
		QueryExecutionId: aws.String("test-query-1234"),
	}, nil).Twice()
	mockAthena.On("GetQueryExecution", mock.Anything).Return(&athena.GetQueryExecutionOutput{
		QueryExecution: &athena.QueryExecution{
			QueryExecutionId: aws.String("test-query-1234"),
			Status: &athena.QueryExecutionStatus{
				State: aws.String(athena.QueryExecutionStateSucceeded),
			},
		},
	}, nil).Twice()
	mockAthena.On("GetQueryResults", mock.Anything).Return(&athena.GetQueryResultsOutput{}, nil).Twice()

	out, err := apiTest.PutIntegration(&models.PutIntegrationInput{
		PutIntegrationSettings: models.PutIntegrationSettings{
			AWSAccountID:     aws.String(testAccountID),
			IntegrationLabel: aws.String(testIntegrationLabel),
			IntegrationType:  aws.String(models.IntegrationTypeAWS3),
			UserID:           aws.String(testUserID),
			S3Bucket:         aws.String("bucket"),
			KmsKey:           aws.String("keyarns"),
			LogTypes:         aws.StringSlice([]string{"AWS.VPCFlow"}),
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, out)
	mockSQS.AssertExpectations(t)
	mockGlue.AssertExpectations(t)
	mockAthena.AssertExpectations(t)
}

func TestPutLogIntegrationUpdateSqsQueuePermissionsFailure(t *testing.T) {
	dynamoClient = &ddb.DDB{Client: &modelstest.MockDDBClient{TestErr: false}, TableName: "test"}
	mockSQS := &testutils.SqsMock{}
	sqsClient = mockSQS
	env.LogProcessorQueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/testqueue"
	evaluateIntegrationFunc = func(_ API, _ *models.CheckIntegrationInput) (string, bool, error) { return "", true, nil }

	mockSQS.On("GetQueueAttributes", mock.Anything).Return(&sqs.GetQueueAttributesOutput{}, errors.New("error")).Once()

	out, err := apiTest.PutIntegration(&models.PutIntegrationInput{
		PutIntegrationSettings: models.PutIntegrationSettings{
			AWSAccountID:     aws.String(testAccountID),
			IntegrationLabel: aws.String(testIntegrationLabel),
			IntegrationType:  aws.String(models.IntegrationTypeAWS3),
			UserID:           aws.String(testUserID),
			S3Bucket:         aws.String("bucket"),
			KmsKey:           aws.String("keyarns"),
			LogTypes:         aws.StringSlice([]string{"AWS.VPCFlow"}),
		},
	})
	require.Error(t, err)
	require.Empty(t, out)
	mockSQS.AssertExpectations(t)
}
