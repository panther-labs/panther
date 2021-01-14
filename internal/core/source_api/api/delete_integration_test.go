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
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/awssqs"
	"github.com/panther-labs/panther/pkg/genericapi"
)

func TestDeleteIntegrationItem(t *testing.T) {
	t.Parallel()
	apiTest := NewAPITest()

	apiTest.mockDdb.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, nil)
	apiTest.mockDdb.On("GetItem", mock.Anything).Return(generateGetItemOutput(models.IntegrationTypeAWSScan), nil)

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: testIntegrationID,
	})

	assert.NoError(t, result)
	apiTest.AssertExpectations(t)
}

func TestDeleteLogIntegration(t *testing.T) {
	t.Parallel()
	apiTest := NewAPITest()

	apiTest.Config.LogProcessorQueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/testqueue"

	expectedGetQueueAttributesInput := &sqs.GetQueueAttributesInput{
		AttributeNames: aws.StringSlice([]string{"Policy"}),
		QueueUrl:       aws.String(apiTest.Config.LogProcessorQueueURL),
	}

	scanResult := &dynamodb.ScanOutput{
		Items: []map[string]*dynamodb.AttributeValue{
			generateDDBAttributes(models.IntegrationTypeAWS3),
		},
	}

	apiTest.mockDdb.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, nil)
	apiTest.mockDdb.On("GetItem", mock.Anything).Return(generateGetItemOutput(models.IntegrationTypeAWS3), nil)
	apiTest.mockDdb.On("Scan", mock.Anything).Return(scanResult, nil)

	alreadyExistingAttributes := generateQueueAttributeOutput(t, []string{testAccountID})
	apiTest.mockSqs.On("GetQueueAttributes", expectedGetQueueAttributesInput).
		Return(&sqs.GetQueueAttributesOutput{Attributes: alreadyExistingAttributes}, nil)
	expectedAttributes := generateQueueAttributeOutput(t, []string{})
	expectedSetAttributes := &sqs.SetQueueAttributesInput{
		Attributes: expectedAttributes,
		QueueUrl:   aws.String(apiTest.Config.LogProcessorQueueURL),
	}
	apiTest.mockSqs.On("SetQueueAttributes", expectedSetAttributes).Return(&sqs.SetQueueAttributesOutput{}, nil)

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: testIntegrationID,
	})

	assert.NoError(t, result)
	apiTest.AssertExpectations(t)
}

func TestDeleteLogIntegrationKeepSqsQueuePermissions(t *testing.T) {
	// This scenario tests the case where we delete a source
	// but another source for that account exists. In that case we
	// should remove the SQS permissions for that account
	t.Parallel()
	apiTest := NewAPITest()

	apiTest.Config.LogProcessorQueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/testqueue"

	additionLogSourceEntry := generateDDBAttributes(models.IntegrationTypeAWS3)
	additionLogSourceEntry["integrationId"] = &dynamodb.AttributeValue{
		// modify entry to have different ID
		S: aws.String(testIntegrationID + "-2"),
	}
	scanResult := &dynamodb.ScanOutput{
		Items: []map[string]*dynamodb.AttributeValue{
			generateDDBAttributes(models.IntegrationTypeAWS3),
			additionLogSourceEntry,
		},
	}

	apiTest.mockDdb.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, nil)
	apiTest.mockDdb.On("GetItem", mock.Anything).Return(generateGetItemOutput(models.IntegrationTypeAWS3), nil)
	apiTest.mockDdb.On("Scan", mock.Anything).Return(scanResult, nil)

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: testIntegrationID,
	})

	assert.NoError(t, result)
	apiTest.AssertExpectations(t)
}

func TestDeleteIntegrationItemError(t *testing.T) {
	t.Parallel()
	apiTest := NewAPITest()

	mockErr := awserr.New(
		"ErrCodeInternalServerError",
		"An error occurred on the server side.",
		errors.New("fake error"),
	)
	apiTest.mockDdb.On("GetItem", mock.Anything).Return(generateGetItemOutput(models.IntegrationTypeAWSScan), nil)
	apiTest.mockDdb.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, mockErr)

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: testIntegrationID,
	})

	assert.Error(t, result)
	apiTest.AssertExpectations(t)
}
func TestDeleteIntegrationPolicyNotFound(t *testing.T) {
	t.Parallel()
	apiTest := NewAPITest()

	apiTest.Config.LogProcessorQueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/testqueue"

	expectedGetQueueAttributesInput := &sqs.GetQueueAttributesInput{
		AttributeNames: aws.StringSlice([]string{"Policy"}),
		QueueUrl:       aws.String(apiTest.Config.LogProcessorQueueURL),
	}

	scanResult := &dynamodb.ScanOutput{
		Items: []map[string]*dynamodb.AttributeValue{
			generateDDBAttributes(models.IntegrationTypeAWS3),
		},
	}
	apiTest.mockDdb.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, nil)
	apiTest.mockDdb.On("GetItem", mock.Anything).Return(generateGetItemOutput(models.IntegrationTypeAWS3), nil)
	apiTest.mockDdb.On("Scan", mock.Anything).Return(scanResult, nil)

	alreadyExistingAttributes := generateQueueAttributeOutput(t, []string{"111111111111"}) // Wrong accountID
	apiTest.mockSqs.On("GetQueueAttributes", expectedGetQueueAttributesInput).
		Return(&sqs.GetQueueAttributesOutput{Attributes: alreadyExistingAttributes}, nil)

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: testIntegrationID,
	})

	assert.NoError(t, result)
	apiTest.AssertExpectations(t)
}

func TestDeleteIntegrationItemDoesNotExist(t *testing.T) {
	t.Parallel()
	apiTest := NewAPITest()

	apiTest.mockDdb.On("GetItem", mock.Anything).Return(&dynamodb.GetItemOutput{}, nil)

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: testIntegrationID,
	})

	assert.Error(t, result)
	assert.IsType(t, &genericapi.DoesNotExistError{}, result)
	apiTest.AssertExpectations(t)
}

func TestDeleteIntegrationDeleteOfItemFails(t *testing.T) {
	t.Parallel()
	apiTest := NewAPITest()

	apiTest.Config.LogProcessorQueueURL = "https://sqs.eu-west-1.amazonaws.com/123456789012/testqueue"

	scanResult := &dynamodb.ScanOutput{
		Items: []map[string]*dynamodb.AttributeValue{
			generateDDBAttributes(models.IntegrationTypeAWS3),
		},
	}

	apiTest.mockDdb.On("DeleteItem", mock.Anything).Return(&dynamodb.DeleteItemOutput{}, errors.New("error"))
	apiTest.mockDdb.On("GetItem", mock.Anything).Return(generateGetItemOutput(models.IntegrationTypeAWS3), nil)
	apiTest.mockDdb.On("Scan", mock.Anything).Return(scanResult, nil)

	alreadyExistingAttributes := generateQueueAttributeOutput(t, []string{testAccountID})
	apiTest.mockSqs.On("GetQueueAttributes", mock.Anything).
		Return(&sqs.GetQueueAttributesOutput{Attributes: alreadyExistingAttributes}, nil).Once()
	apiTest.mockSqs.On("SetQueueAttributes", mock.Anything).Return(&sqs.SetQueueAttributesOutput{}, nil).Once()

	result := apiTest.DeleteIntegration(&models.DeleteIntegrationInput{
		IntegrationID: testIntegrationID,
	})

	assert.Error(t, result)
	apiTest.AssertExpectations(t)
}

func generateGetItemOutput(integrationType string) *dynamodb.GetItemOutput {
	return &dynamodb.GetItemOutput{
		Item: generateDDBAttributes(integrationType),
	}
}

func generateDDBAttributes(integrationType string) map[string]*dynamodb.AttributeValue {
	return map[string]*dynamodb.AttributeValue{
		"integrationId":   {S: aws.String(testIntegrationID)},
		"integrationType": {S: &integrationType},
		"awsAccountId":    {S: aws.String(testAccountID)},
	}
}

func generateQueueAttributeOutput(t *testing.T, accountIDs []string) map[string]*string {
	policyAttribute := aws.String("")
	if len(accountIDs) > 0 {
		statements := make([]awssqs.SqsPolicyStatement, len(accountIDs))
		for i, accountID := range accountIDs {
			statements[i] = awssqs.SqsPolicyStatement{
				SID:       fmt.Sprintf("PantherSubscriptionSID-%s", accountID),
				Effect:    "Allow",
				Principal: map[string]string{"AWS": "*"},
				Action:    "sqs:SendMessage",
				Resource:  "*",
				Condition: map[string]interface{}{
					"ArnLike": map[string]string{
						"aws:SourceArn": fmt.Sprintf("arn:aws:sns:*:%s:*", accountID),
					},
				},
			}
		}
		policy := awssqs.SqsPolicy{
			Version:    "2008-10-17",
			Statements: statements,
		}

		marshaledPolicy, err := jsoniter.MarshalToString(policy)
		require.NoError(t, err)
		policyAttribute = aws.String(marshaledPolicy)
	}

	return map[string]*string{
		"Policy": policyAttribute,
	}
}
