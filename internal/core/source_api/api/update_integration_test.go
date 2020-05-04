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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/internal/core/source_api/ddb/modelstest"
)

func TestUpdateIntegrationSettings(t *testing.T) {
	mockClient := &modelstest.MockDDBClient{}
	dynamoClient = &ddb.DDB{Client: mockClient, TableName: "test"}
	evaluateIntegrationFunc = func(_ API, _ *models.CheckIntegrationInput) (string, bool, error) { return "", true, nil }

	getResponse := &dynamodb.GetItemOutput{Item: map[string]*dynamodb.AttributeValue{
		"AWSAccountID":  {S: aws.String("123456789012")},
		"IntegrationID": {S: aws.String("1111111")},
	}}
	mockClient.On("GetItem", mock.Anything).Return(getResponse, nil)

	updateResponse := &dynamodb.UpdateItemOutput{Attributes: map[string]*dynamodb.AttributeValue{
		"awsAccountId": {
			S: aws.String("123456789012"),
		},
	}}
	mockClient.On("UpdateItem", mock.Anything).Return(updateResponse, nil)

	result, err := apiTest.UpdateIntegrationSettings(&models.UpdateIntegrationSettingsInput{
		IntegrationID:    aws.String(testIntegrationID),
		IntegrationLabel: aws.String("NewAWSTestingAccount"),
		ScanIntervalMins: aws.Int(1440),
	})

	expected := &models.SourceIntegration{
		SourceIntegrationMetadata: &models.SourceIntegrationMetadata{
			AWSAccountID: aws.String("123456789012"),
		},
	}
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	mockClient.AssertExpectations(t)
}

func TestUpdateIntegrationSettingsAwsS3Type(t *testing.T) {
	mockClient := &modelstest.MockDDBClient{}
	dynamoClient = &ddb.DDB{Client: mockClient, TableName: "test"}

	getResponse := &dynamodb.GetItemOutput{Item: map[string]*dynamodb.AttributeValue{
		"AWSAccountID":  {S: aws.String("123456789012")},
		"IntegrationID": {S: aws.String("1111111")},
	}}
	mockClient.On("GetItem", mock.Anything).Return(getResponse, nil)

	resp := &dynamodb.UpdateItemOutput{}
	mockClient.On("UpdateItem", mock.Anything).Return(resp, nil)

	result, err := apiTest.UpdateIntegrationSettings(&models.UpdateIntegrationSettingsInput{
		S3Bucket: aws.String("test-bucket-1"),
		S3Prefix: aws.String("prefix/"),
		KmsKey:   aws.String("arn:aws:kms:us-west-2:111111111111:key/27803c7e-9fa5-4fcb-9525-ee11c953d329"),
		LogTypes: aws.StringSlice([]string{"logType1", "logType2"}),
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	mockClient.AssertExpectations(t)
}

func TestUpdateIntegrationValidTime(t *testing.T) {
	now := time.Now()
	validator, err := models.Validator()
	require.NoError(t, err)
	assert.NoError(t, validator.Struct(&models.UpdateIntegrationLastScanStartInput{
		IntegrationID:     aws.String(testIntegrationID),
		ScanStatus:        aws.String(models.StatusOK),
		LastScanStartTime: &now,
	}))
}

func TestUpdateIntegrationLastScanStart(t *testing.T) {
	mockClient := &modelstest.MockDDBClient{}
	dynamoClient = &ddb.DDB{Client: mockClient, TableName: "test"}

	resp := &dynamodb.UpdateItemOutput{}
	mockClient.On("UpdateItem", mock.Anything).Return(resp, nil)

	lastScanEndTime, err := time.Parse(time.RFC3339, "2009-11-10T23:00:00Z")
	require.NoError(t, err)

	result, err := apiTest.UpdateIntegrationLastScanStart(&models.UpdateIntegrationLastScanStartInput{
		IntegrationID:     aws.String(testIntegrationID),
		LastScanStartTime: &lastScanEndTime,
		ScanStatus:        aws.String(models.StatusOK),
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	mockClient.AssertExpectations(t)
}

func TestUpdateIntegrationLastScanEnd(t *testing.T) {
	mockClient := &modelstest.MockDDBClient{}
	dynamoClient = &ddb.DDB{Client: mockClient, TableName: "test"}

	resp := &dynamodb.UpdateItemOutput{}

	update := expression.Set(
		expression.Name("lastScanEndTime"),
		expression.Value("2009-11-10T23:00:00Z"),
	)
	update = update.Set(
		expression.Name("lastScanErrorMessage"),
		expression.Value("something went wrong"),
	)
	update = update.Set(
		expression.Name("scanStatus"),
		expression.Value(models.StatusError),
	)
	expr, err := expression.NewBuilder().WithUpdate(update).Build()
	require.NoError(t, err)

	expected := &dynamodb.UpdateItemInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Key: map[string]*dynamodb.AttributeValue{
			"integrationId": {S: aws.String(testIntegrationID)},
		},
		ReturnValues:     aws.String("ALL_NEW"),
		TableName:        aws.String("test"),
		UpdateExpression: expr.Update(),
	}
	mockClient.On("UpdateItem", expected).Return(resp, nil)

	lastScanEndTime, err := time.Parse(time.RFC3339, "2009-11-10T23:00:00Z")
	require.NoError(t, err)

	result, err := apiTest.UpdateIntegrationLastScanEnd(&models.UpdateIntegrationLastScanEndInput{
		IntegrationID:        aws.String(testIntegrationID),
		LastScanEndTime:      &lastScanEndTime,
		LastScanErrorMessage: aws.String("something went wrong"),
		ScanStatus:           aws.String(models.StatusError),
	})

	assert.NoError(t, err)
	assert.NotNil(t, result)
	mockClient.AssertExpectations(t)
}
