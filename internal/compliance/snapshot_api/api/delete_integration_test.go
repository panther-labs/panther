package api

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
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/panther-labs/panther/api/lambda/snapshot/models"
	"github.com/panther-labs/panther/internal/compliance/snapshot_api/ddb"
	"github.com/panther-labs/panther/pkg/genericapi"
)

type mockDDBClient struct {
	dynamodbiface.DynamoDBAPI
	mock.Mock
}

func (client *mockDDBClient) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	args := client.Called(input)
	return args.Get(0).(*dynamodb.GetItemOutput), args.Error(1)
}

func (client *mockDDBClient) DeleteItem(input *dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error) {
	args := client.Called(input)
	return args.Get(0).(*dynamodb.DeleteItemOutput), args.Error(1)
}

func TestDeleteIntegrationItem(t *testing.T) {
	mockClient := &mockDDBClient{}
	db = &ddb.DDB{Client: mockClient, TableName: "test"}

	mockClient.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, nil)
	mockClient.On("GetItem", mock.Anything).Return(getItem(models.IntegrationTypeAWSScan), nil)

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: aws.String(testIntegrationID),
	})

	assert.NoError(t, result)
	mockClient.AssertExpectations(t)
}

func TestDeleteIntegrationItemLogAnalysis(t *testing.T) {
	mockClient := &mockDDBClient{}
	db = &ddb.DDB{Client: mockClient, TableName: "test"}

	mockSqs := &mockSQSClient{}
	SQSClient = mockSqs
	logProcessorQueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/testqueue"

	expectedGetQueueAttributesInput := &sqs.GetQueueAttributesInput{
		AttributeNames: aws.StringSlice([]string{"Policy"}),
		QueueUrl:       aws.String(logProcessorQueueURL),
	}

	mockClient.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, nil)
	mockClient.On("GetItem", mock.Anything).Return(getItem(models.IntegrationTypeAWS3), nil)

	alreadyExistingAttributes := generateQueueAttributeOutput(t, []string{testAccountID})
	mockSqs.On("GetQueueAttributes", expectedGetQueueAttributesInput).
		Return(&sqs.GetQueueAttributesOutput{Attributes: alreadyExistingAttributes}, nil)
	expectedAttributes := generateQueueAttributeOutput(t, []string{})
	expectedSetAttributes := &sqs.SetQueueAttributesInput{
		Attributes: expectedAttributes,
		QueueUrl:   aws.String(logProcessorQueueURL),
	}
	mockSqs.On("SetQueueAttributes", expectedSetAttributes).Return(&sqs.SetQueueAttributesOutput{}, nil)

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: aws.String(testIntegrationID),
	})

	assert.NoError(t, result)
	mockClient.AssertExpectations(t)
}

func TestDeleteIntegrationItemError(t *testing.T) {
	mockClient := &mockDDBClient{}
	db = &ddb.DDB{Client: mockClient, TableName: "test"}

	mockErr := awserr.New(
		"ErrCodeInternalServerError",
		"An error occurred on the server side.",
		errors.New("fake error"),
	)
	mockClient.On("GetItem", mock.Anything).Return(getItem(models.IntegrationTypeAWSScan), nil)
	mockClient.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, mockErr)

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: aws.String(testIntegrationID),
	})

	assert.Error(t, result)
	mockClient.AssertExpectations(t)
}

func TestDeleteIntegrationItemDoesNotExist(t *testing.T) {
	mockClient := &mockDDBClient{}
	db = &ddb.DDB{Client: mockClient, TableName: "test"}

	mockClient.On("GetItem", mock.Anything).Return(&dynamodb.GetItemOutput{}, nil)

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: aws.String(testIntegrationID),
	})

	assert.Error(t, result)
	assert.IsType(t, &genericapi.DoesNotExistError{}, result)
	mockClient.AssertExpectations(t)
}

func TestDeleteIntegrationDeleteOfItemFails(t *testing.T) {
	mockClient := &mockDDBClient{}
	db = &ddb.DDB{Client: mockClient, TableName: "test"}

	mockSqs := &mockSQSClient{}
	SQSClient = mockSqs
	logProcessorQueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/testqueue"

	mockClient.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, errors.New("error"))
	mockClient.On("GetItem", mock.Anything).Return(getItem(models.IntegrationTypeAWS3), nil)

	alreadyExistingAttributes := generateQueueAttributeOutput(t, []string{testAccountID})
	mockSqs.On("GetQueueAttributes", mock.Anything).Return(&sqs.GetQueueAttributesOutput{Attributes: alreadyExistingAttributes}, nil).Twice()
	mockSqs.On("SetQueueAttributes", mock.Anything).Return(&sqs.SetQueueAttributesOutput{}, nil).Twice()

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: aws.String(testIntegrationID),
	})

	assert.Error(t, result)
	mockClient.AssertExpectations(t)
}

func TestDeleteIntegrationDeleteRecoveryFails(t *testing.T) {
	// Used to capture logs for unit testing purposes
	core, recordedLogs := observer.New(zapcore.ErrorLevel)
	zap.ReplaceGlobals(zap.New(core))

	mockClient := &mockDDBClient{}
	db = &ddb.DDB{Client: mockClient, TableName: "test"}

	mockSqs := &mockSQSClient{}
	SQSClient = mockSqs
	logProcessorQueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/testqueue"

	mockClient.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, errors.New("error"))
	mockClient.On("GetItem", mock.Anything).Return(getItem(models.IntegrationTypeAWS3), nil)
	alreadyExistingAttributes := generateQueueAttributeOutput(t, []string{testAccountID})
	mockSqs.On("GetQueueAttributes", mock.Anything).Return(&sqs.GetQueueAttributesOutput{Attributes: alreadyExistingAttributes}, nil).Twice()
	mockSqs.On("SetQueueAttributes", mock.Anything).Return(&sqs.SetQueueAttributesOutput{}, nil).Once()
	mockSqs.On("SetQueueAttributes", mock.Anything).Return(&sqs.SetQueueAttributesOutput{}, errors.New("error")).Once()

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: aws.String(testIntegrationID),
	})

	require.Error(t, result)
	// verifying we log appropriate message
	errorLog := recordedLogs.FilterMessage("failed to re-add SQS permission for integration. " +
		"SQS is missing permissions that have to be added manually")
	require.NotNil(t, errorLog)
	mockClient.AssertExpectations(t)
}

func getItem(integrationType string) *dynamodb.GetItemOutput {
	return &dynamodb.GetItemOutput{
		Item: map[string]*dynamodb.AttributeValue{
			"integrationId":   {S: aws.String(testIntegrationID)},
			"integrationType": {S: aws.String(integrationType)},
			"awsAccountId":    {S: aws.String(testAccountID)},
		},
	}
}

func generateQueueAttributeOutput(t *testing.T, accountIDs []string) map[string]*string {
	statements := make([]SqsPolicyStatement, len(accountIDs))
	for i, accountID := range accountIDs {
		statements[i] = SqsPolicyStatement{
			SID:       fmt.Sprintf("PantherSubscriptionSID-%s", accountID),
			Effect:    "Allow",
			Principal: map[string]string{"AWS": "*"},
			Action:    "sqs:SendMessage",
			Resource:  logProcessorQueueArn,
			Condition: map[string]interface{}{
				"ArnLike": map[string]string{
					"aws:SourceArn": fmt.Sprintf("arn:aws:sns:*:%s:*", accountID),
				},
			},
		}
	}
	policy := SqsPolicy{
		Version:    "2008-10-17",
		Statements: statements,
	}

	marshalledPolicy, err := jsoniter.MarshalToString(policy)
	require.NoError(t, err)
	return map[string]*string{
		"Policy": aws.String(marshalledPolicy),
	}
}
