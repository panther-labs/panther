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
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestUpdateIntegrationSettingsAwsScanType(t *testing.T) {
	mockClient := &testutils.DynamoDBMock{}
	dynamoClient = &ddb.DDB{Client: mockClient, TableName: "test"}
	mockSQS := &testutils.SqsMock{}

	// Mocking health check
	evaluateIntegrationFunc = func(_ API, _ *models.CheckIntegrationInput) (string, bool, error) {
		return "", true, nil
	}

	getResponse := &dynamodb.GetItemOutput{Item: map[string]*dynamodb.AttributeValue{
		"integrationId":   {S: aws.String(testIntegrationID)},
		"integrationType": {S: aws.String(models.IntegrationTypeAWSScan)},
	}}
	mockClient.On("GetItem", mock.Anything).Return(getResponse, nil).Once()
	mockClient.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, nil).Once()
	mockClient.On("Scan", mock.Anything).Return(&dynamodb.ScanOutput{}, nil).Once()
	mockSQS.On("SendMessageWithContext", mock.Anything, mock.Anything).Return(&sqs.SendMessageOutput{}, nil)

	result, err := apiTest.UpdateIntegrationSettings(&models.UpdateIntegrationSettingsInput{
		IntegrationID:    testIntegrationID,
		IntegrationLabel: "new-label",
		ScanIntervalMins: 1440,
	})

	expected := &models.SourceIntegration{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			IntegrationID:    testIntegrationID,
			IntegrationType:  models.IntegrationTypeAWSScan,
			IntegrationLabel: "new-label",
			ScanIntervalMins: 1440,
		},
	}
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	mockClient.AssertExpectations(t)
}

func TestUpdateIntegrationSettingsAwsS3Type(t *testing.T) {
	mockClient := &testutils.DynamoDBMock{}
	dynamoClient = &ddb.DDB{Client: mockClient, TableName: "test"}
	mockSqsClient := &testutils.SqsMock{}
	sqsClient = mockSqsClient

	// Mocking health check
	evaluateIntegrationFunc = func(api API, integration *models.CheckIntegrationInput) (string, bool, error) {
		return "", true, nil
	}

	getResponse := &dynamodb.GetItemOutput{Item: map[string]*dynamodb.AttributeValue{
		"integrationId":   {S: aws.String(testIntegrationID)},
		"integrationType": {S: aws.String(models.IntegrationTypeAWS3)},
		"logTypes":        {SS: aws.StringSlice([]string{"Log.TypeA"})},
	}}
	mockClient.On("GetItem", mock.Anything).Return(getResponse, nil).Once()
	mockClient.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, nil).Once()
	mockClient.On("Scan", mock.Anything).Return(&dynamodb.ScanOutput{}, nil).Once()
	// Send message to create new log types
	mockSqsClient.On("SendMessageWithContext", mock.Anything, mock.Anything).Return(&sqs.SendMessageOutput{}, nil)

	result, err := apiTest.UpdateIntegrationSettings(&models.UpdateIntegrationSettingsInput{
		S3Bucket: "test-bucket-1",
		S3Prefix: "prefix/",
		KmsKey:   "arn:aws:kms:us-west-2:111111111111:key/27803c7e-9fa5-4fcb-9525-ee11c953d329",
		LogTypes: []string{"Log.TypeB"},
	})

	expected := &models.SourceIntegration{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			IntegrationID:   testIntegrationID,
			IntegrationType: models.IntegrationTypeAWS3,
			S3Bucket:        "test-bucket-1",
			S3Prefix:        "prefix/",
			KmsKey:          "arn:aws:kms:us-west-2:111111111111:key/27803c7e-9fa5-4fcb-9525-ee11c953d329",
			LogTypes:        []string{"Log.TypeB"},
		},
	}
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	mockClient.AssertExpectations(t)
	mockSqsClient.AssertExpectations(t)
}

func TestUpdateIntegrationSameLogtypes(t *testing.T) {
	mockClient := &testutils.DynamoDBMock{}
	dynamoClient = &ddb.DDB{Client: mockClient, TableName: "test"}
	// Mocking health check
	evaluateIntegrationFunc = func(api API, integration *models.CheckIntegrationInput) (string, bool, error) {
		return "", true, nil
	}

	getResponse := &dynamodb.GetItemOutput{Item: map[string]*dynamodb.AttributeValue{
		"integrationId":   {S: aws.String(testIntegrationID)},
		"integrationType": {S: aws.String(models.IntegrationTypeAWS3)},
		"logTypes":        {SS: aws.StringSlice([]string{"Log.TypeA"})},
	}}
	mockClient.On("GetItem", mock.Anything).Return(getResponse, nil)
	mockClient.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, nil)
	mockClient.On("Scan", mock.Anything).Return(&dynamodb.ScanOutput{}, nil)

	result, err := apiTest.UpdateIntegrationSettings(&models.UpdateIntegrationSettingsInput{
		S3Bucket: "test-bucket-1",
		S3Prefix: "prefix/",
		KmsKey:   "arn:aws:kms:us-west-2:111111111111:key/27803c7e-9fa5-4fcb-9525-ee11c953d329",
		LogTypes: []string{"Log.TypeA"},
	})

	expected := &models.SourceIntegration{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			IntegrationID:   testIntegrationID,
			IntegrationType: models.IntegrationTypeAWS3,
			S3Bucket:        "test-bucket-1",
			S3Prefix:        "prefix/",
			KmsKey:          "arn:aws:kms:us-west-2:111111111111:key/27803c7e-9fa5-4fcb-9525-ee11c953d329",
			LogTypes:        []string{"Log.TypeA"},
		},
	}
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	mockClient.AssertExpectations(t)
}

func TestUpdateIntegrationValidTime(t *testing.T) {
	now := time.Now()
	validator, err := models.Validator()
	require.NoError(t, err)
	assert.NoError(t, validator.Struct(&models.UpdateIntegrationLastScanStartInput{
		IntegrationID:     testIntegrationID,
		ScanStatus:        models.StatusOK,
		LastScanStartTime: now,
	}))
}

func TestUpdateIntegrationLastScanStart(t *testing.T) {
	mockClient := &testutils.DynamoDBMock{}
	dynamoClient = &ddb.DDB{Client: mockClient, TableName: "test"}

	getResponse := &dynamodb.GetItemOutput{Item: map[string]*dynamodb.AttributeValue{
		"integrationId": {S: aws.String(testIntegrationID)},
	}}
	mockClient.On("GetItem", mock.Anything).Return(getResponse, nil)
	mockClient.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, nil)

	lastScanEndTime, err := time.Parse(time.RFC3339, "2009-11-10T23:00:00Z")
	require.NoError(t, err)

	err = apiTest.UpdateIntegrationLastScanStart(&models.UpdateIntegrationLastScanStartInput{
		IntegrationID:     testIntegrationID,
		LastScanStartTime: lastScanEndTime,
		ScanStatus:        models.StatusOK,
	})

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestUpdateIntegrationLastScanEnd(t *testing.T) {
	mockClient := &testutils.DynamoDBMock{}
	dynamoClient = &ddb.DDB{Client: mockClient, TableName: "test"}

	getResponse := &dynamodb.GetItemOutput{Item: map[string]*dynamodb.AttributeValue{
		"integrationId": {S: aws.String(testIntegrationID)},
	}}
	mockClient.On("GetItem", mock.Anything).Return(getResponse, nil)
	mockClient.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, nil)

	lastScanEndTime, err := time.Parse(time.RFC3339, "2009-11-10T23:00:00Z")
	require.NoError(t, err)

	err = apiTest.UpdateIntegrationLastScanEnd(&models.UpdateIntegrationLastScanEndInput{
		IntegrationID:        testIntegrationID,
		LastScanEndTime:      lastScanEndTime,
		LastScanErrorMessage: "something went wrong",
		ScanStatus:           models.StatusError,
	})

	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

func TestSlicesContainSameElements(t *testing.T) {
	type testCase struct {
		old, new []string
		expect   bool
	}

	for i, tc := range []testCase{
		{
			old:    []string{},
			new:    []string{},
			expect: false,
		},
		{
			old:    []string{"Log.A"},
			new:    []string{},
			expect: false,
		},
		{
			old:    []string{},
			new:    []string{"Log.A"},
			expect: true,
		},
		{
			old:    []string{"Log.A", "Log.B"},
			new:    []string{"Log.A", "Log.A", "Log.B"},
			expect: false,
		},
		{
			old:    []string{"Log.A", "Log.B", "Log.A"},
			new:    []string{"Log.A", "Log.B"},
			expect: false,
		},
		{
			old:    []string{"Log.A", "Log.B"},
			new:    []string{"Log.A", "Log.B"},
			expect: false,
		},
		{
			old:    []string{"Log.A", "Log.B"},
			new:    []string{"Log.B", "Log.A"},
			expect: false,
		},
		{
			old:    []string{"Log.A", "Log.B"},
			new:    []string{"Log.A", "Log.B", "Log.C"},
			expect: true,
		},
		{
			old:    []string{"Log.A", "Log.B"},
			new:    []string{"Log.A"},
			expect: false,
		},
		{
			old:    []string{"Log.A", "Log.B"},
			new:    []string{"Log.C", "Log.D"},
			expect: true,
		},
	} {
		tc := tc
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			result := newLogsAdded(tc.old, tc.new)
			assert.Equal(t, tc.expect, result)
		})
	}
}
