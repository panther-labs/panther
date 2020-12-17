package forwarder

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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/forwarder/diff"
	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/forwarder/events"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestComplianceEventWithoutChange(t *testing.T) {
	t.Parallel()
	lambdaMock := &testutils.LambdaMock{}
	firehoseMock := &testutils.FirehoseMock{}

	sh := StreamHandler{
		LambdaClient:   lambdaMock,
		FirehoseClient: firehoseMock,
		StreamName:     "stream-name",
	}

	record := events.DynamoDBEventRecord{
		AWSRegion:      "eu-west-1",
		EventSource:    "aws:dynamodb",
		EventName:      "MODIFY",
		EventID:        "a04e16d70e2520ff8a3569354b55b3f5",
		EventVersion:   "1.1",
		EventSourceArn: "arn:aws:dynamodb:eu-west-1:123456789012:table/panther-compliance/stream/2020-12-09T13:15:55.723",
		Change: events.DynamoDBStreamRecord{
			Keys: map[string]*dynamodb.AttributeValue{
				"resourceId": {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"policyId":   {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
			},
			NewImage: map[string]*dynamodb.AttributeValue{
				"resourceId":     {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"integrationId":  {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				"resourceType":   {S: aws.String("AWS.S3.Bucket")},
				"status":         {S: aws.String("PASS")},
				"lastUpdated":    {S: aws.String("2020-12-09T15:32:32.362503673Z")},
				"policySeverity": {S: aws.String("INFO")},
				"policyId":       {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
				"errorMessage":   {NULL: aws.Bool(true)},
				"suppressed":     {BOOL: aws.Bool(false)},
				"expiresAt":      {N: aws.String("1607707952")},
			},

			OldImage: map[string]*dynamodb.AttributeValue{
				"resourceId":     {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"integrationId":  {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				"resourceType":   {S: aws.String("AWS.S3.Bucket")},
				"status":         {S: aws.String("PASS")},
				"lastUpdated":    {S: aws.String("2020-12-09T14:36:18.288334104Z")},
				"policySeverity": {S: aws.String("INFO")},
				"policyId":       {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
				"errorMessage":   {NULL: aws.Bool(true)},
				"suppressed":     {BOOL: aws.Bool(false)},
				"expiresAt":      {N: aws.String("1607704578")},
			},
		},
	}

	assert.NoError(t, sh.Run(context.Background(), zap.L(), &events.DynamoDBEvent{Records: []events.DynamoDBEventRecord{record}}))
	lambdaMock.AssertExpectations(t)
	firehoseMock.AssertExpectations(t)
}

func TestComplianceEventStatusChange(t *testing.T) {
	t.Parallel()
	lambdaMock := &testutils.LambdaMock{}
	firehoseMock := &testutils.FirehoseMock{}

	sh := StreamHandler{
		LambdaClient:   lambdaMock,
		FirehoseClient: firehoseMock,
		StreamName:     "stream-name",
	}

	record := events.DynamoDBEventRecord{
		AWSRegion:      "eu-west-1",
		EventSource:    "aws:dynamodb",
		EventName:      "MODIFY",
		EventID:        "a04e16d70e2520ff8a3569354b55b3f5",
		EventVersion:   "1.1",
		EventSourceArn: "arn:aws:dynamodb:eu-west-1:123456789012:table/panther-compliance/stream/2020-12-09T13:15:55.723",
		Change: events.DynamoDBStreamRecord{
			Keys: map[string]*dynamodb.AttributeValue{
				"resourceId": {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"policyId":   {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
			},
			NewImage: map[string]*dynamodb.AttributeValue{
				"resourceId":     {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"integrationId":  {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				"resourceType":   {S: aws.String("AWS.S3.Bucket")},
				"status":         {S: aws.String("FAIL")},
				"lastUpdated":    {S: aws.String("2020-12-09T15:32:32.362503673Z")},
				"policySeverity": {S: aws.String("INFO")},
				"policyId":       {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
				"errorMessage":   {NULL: aws.Bool(true)},
				"suppressed":     {BOOL: aws.Bool(false)},
				"expiresAt":      {N: aws.String("1607707952")},
			},

			OldImage: map[string]*dynamodb.AttributeValue{
				"resourceId":     {S: aws.String("arn:aws:s3:::panther-bootstrap-auditlogs")},
				"integrationId":  {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				"resourceType":   {S: aws.String("AWS.S3.Bucket")},
				"status":         {S: aws.String("PASS")},
				"lastUpdated":    {S: aws.String("2020-12-09T14:36:18.288334104Z")},
				"policySeverity": {S: aws.String("INFO")},
				"policyId":       {S: aws.String("AWS.S3.Bucket.NameDNSCompliance")},
				"errorMessage":   {NULL: aws.Bool(true)},
				"suppressed":     {BOOL: aws.Bool(false)},
				"expiresAt":      {N: aws.String("1607704578")},
			},
		},
	}

	// Mock fetching of integration label
	integrations := []*models.SourceIntegrationMetadata{
		{
			IntegrationID:    "8349b647-f731-48c4-9d6b-eefff4010c14",
			IntegrationLabel: "test-label",
		},
	}
	marshaledIntegrations, err := jsoniter.Marshal(integrations)
	assert.NoError(t, err)
	lambdaMock.On("Invoke", mock.Anything).Return(&lambda.InvokeOutput{Payload: marshaledIntegrations}, nil).Once()

	// Mock sending data to firehose

	// Expected Firehose payload
	change := ComplianceChange{
		ChangeType:       "MODIFIED",
		IntegrationID:    "8349b647-f731-48c4-9d6b-eefff4010c14",
		IntegrationLabel: "test-label",
		LastUpdated:      "2020-12-09T15:32:32.362503673Z",
		PolicyID:         "AWS.S3.Bucket.NameDNSCompliance",
		PolicySeverity:   "INFO",
		ResourceID:       "arn:aws:s3:::panther-bootstrap-auditlogs",
		ResourceType:     "AWS.S3.Bucket",
		Status:           "FAIL",
		Suppressed:       false,
	}
	changeMarshalled, err := jsoniter.Marshal(change)
	assert.NoError(t, err)
	expectedRequest := &firehose.PutRecordBatchInput{
		DeliveryStreamName: aws.String("stream-name"),
		Records: []*firehose.Record{
			{
				Data: append(changeMarshalled, '\n'),
			},
		},
	}
	firehoseMock.On("PutRecordBatchWithContext", mock.Anything, expectedRequest, mock.Anything).
		Return(&firehose.PutRecordBatchOutput{}, nil).
		Once()

	// Run test & final assertions
	assert.NoError(t, sh.Run(context.Background(), zap.L(), &events.DynamoDBEvent{Records: []events.DynamoDBEventRecord{record}}))
	lambdaMock.AssertExpectations(t)
	firehoseMock.AssertExpectations(t)
}

func TestResourceEvent(t *testing.T) {
	t.Parallel()
	lambdaMock := &testutils.LambdaMock{}
	firehoseMock := &testutils.FirehoseMock{}

	sh := StreamHandler{
		LambdaClient:   lambdaMock,
		FirehoseClient: firehoseMock,
		StreamName:     "stream-name",
	}

	record := events.DynamoDBEventRecord{
		AWSRegion:      "eu-west-1",
		EventSource:    "aws:dynamodb",
		EventName:      "MODIFY",
		EventID:        "a04e16d70e2520ff8a3569354b55b3f5",
		EventVersion:   "1.1",
		EventSourceArn: "arn:aws:dynamodb:eu-west-1:123456789012:table/panther-resources/stream/2020-12-09T13:15:55.703",
		Change: events.DynamoDBStreamRecord{
			Keys: map[string]*dynamodb.AttributeValue{
				"id": {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
			},
			NewImage: map[string]*dynamodb.AttributeValue{
				"id":              {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"lowerId":         {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"expiresAt":       {N: aws.String("1607707952")},
				"integrationId":   {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				"deleted":         {BOOL: aws.Bool(false)},
				"integrationType": {S: aws.String("aws")},
				"type":            {S: aws.String("AWS.Lambda.Function")},
				"lastModified":    {S: aws.String("2020-12-09T15:32:32.362503673Z")},
				"attributes": {M: map[string]*dynamodb.AttributeValue{
					"Policy":       {NULL: aws.Bool(true)},
					"RevisionId":   {S: aws.String("433968bb-c360-4411-8f38-0ac65767f230")},
					"LastModified": {S: aws.String("2020-12-15T11:10:32.883+0000")},
					"MemorySize":   {N: aws.String("128")},
					"ResourceId":   {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"TimeCreated":  {NULL: aws.Bool(true)},
					"Region":       {S: aws.String("eu-west-1")},
					"Arn":          {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"ResourceType": {S: aws.String("AWS.Lambda.Function")},
					"AccountId":    {S: aws.String("123456789012")},
					"Name":         {S: aws.String("panther")},
					"Tags": {M: map[string]*dynamodb.AttributeValue{
						"key": {S: aws.String("value")},
					}}},
				}},
			OldImage: map[string]*dynamodb.AttributeValue{
				"id":              {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"lowerId":         {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"expiresAt":       {N: aws.String("1607707952")},
				"integrationId":   {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				"deleted":         {BOOL: aws.Bool(false)},
				"integrationType": {S: aws.String("aws")},
				"type":            {S: aws.String("AWS.Lambda.Function")},
				"lastModified":    {S: aws.String("2020-12-09T15:32:32.362503673Z")},
				"attributes": {M: map[string]*dynamodb.AttributeValue{
					"Policy":       {NULL: aws.Bool(true)},
					"RevisionId":   {S: aws.String("433968bb-c360-4411-8f38-0ac65767f230")},
					"LastModified": {S: aws.String("2020-12-15T11:10:32.883+0000")},
					"MemorySize":   {N: aws.String("256")},
					"ResourceId":   {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"TimeCreated":  {NULL: aws.Bool(true)},
					"Region":       {S: aws.String("eu-west-1")},
					"Arn":          {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"ResourceType": {S: aws.String("AWS.Lambda.Function")},
					"AccountId":    {S: aws.String("123456789012")},
					"Name":         {S: aws.String("panther")},
					"Tags": {M: map[string]*dynamodb.AttributeValue{
						"key": {S: aws.String("value")},
					}}},
				},
			},
		},
	}

	// Mock fetching of integration label
	integrations := []*models.SourceIntegrationMetadata{
		{
			IntegrationID:    "8349b647-f731-48c4-9d6b-eefff4010c14",
			IntegrationLabel: "test-label",
		},
	}
	marshaledIntegrations, err := jsoniter.Marshal(integrations)
	assert.NoError(t, err)
	lambdaMock.On("Invoke", mock.Anything).Return(&lambda.InvokeOutput{Payload: marshaledIntegrations}, nil).Once()

	// Mock firehose invocation
	firehoseMock.On("PutRecordBatchWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(&firehose.PutRecordBatchOutput{}, nil).
		Once()

	assert.NoError(t, sh.Run(context.Background(), zap.L(), &events.DynamoDBEvent{Records: []events.DynamoDBEventRecord{record}}))
	lambdaMock.AssertExpectations(t)
	firehoseMock.AssertExpectations(t)

	// Verify firehose payload
	expectedChange := ResourceChange{
		ChangeType:       "MODIFIED",
		IntegrationID:    "8349b647-f731-48c4-9d6b-eefff4010c14",
		IntegrationLabel: "test-label",
		LastUpdated:      "2020-12-09T15:32:32.362503673Z",
		ID:               "arn:aws:lambda:eu-west-1:123456789012:function:panther",
		Changes: map[string]diff.Diff{
			"MemorySize": {
				From: float64(256),
				To:   float64(128),
			},
		},
		ResourceAttributes: ResourceAttributes{
			TimeCreated:  nil,
			Name:         aws.String("panther"),
			ResourceType: aws.String("AWS.Lambda.Function"),
			ResourceID:   aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther"),
			Region:       aws.String("eu-west-1"),
			AccountID:    aws.String("123456789012"),
			ARN:          aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther"),
			Tags: map[string]string{
				"key": "value",
			},
		},
	}

	var expectedResource map[string]interface{}
	if err = dynamodbattribute.Unmarshal(record.Change.NewImage["attributes"], &expectedResource); err != nil {
		t.Error("failed to marshal attributes")
	}
	expectedChange.Resource = expectedResource

	request := firehoseMock.Calls[0].Arguments[1].(*firehose.PutRecordBatchInput)
	assert.Equal(t, 1, len(request.Records))
	assert.Equal(t, "stream-name", *request.DeliveryStreamName)
	var change ResourceChange
	if err := jsoniter.Unmarshal(request.Records[0].Data, &change); err != nil {
		t.Error("failed to unmarshal change")
	}
	assert.Equal(t, expectedChange, change)
}

func TestResourceMarkedDeleted(t *testing.T) {
	t.Parallel()
	lambdaMock := &testutils.LambdaMock{}
	firehoseMock := &testutils.FirehoseMock{}

	sh := StreamHandler{
		LambdaClient:   lambdaMock,
		FirehoseClient: firehoseMock,
		StreamName:     "stream-name",
	}

	record := events.DynamoDBEventRecord{
		AWSRegion:      "eu-west-1",
		EventSource:    "aws:dynamodb",
		EventName:      "MODIFY",
		EventID:        "a04e16d70e2520ff8a3569354b55b3f5",
		EventVersion:   "1.1",
		EventSourceArn: "arn:aws:dynamodb:eu-west-1:123456789012:table/panther-resources/stream/2020-12-09T13:15:55.703",
		Change: events.DynamoDBStreamRecord{
			Keys: map[string]*dynamodb.AttributeValue{
				"id": {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
			},
			NewImage: map[string]*dynamodb.AttributeValue{
				"id":            {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"lowerId":       {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"expiresAt":     {N: aws.String("1607707952")},
				"integrationId": {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				// This source is now deleted
				"deleted":         {BOOL: aws.Bool(true)},
				"integrationType": {S: aws.String("aws")},
				"type":            {S: aws.String("AWS.Lambda.Function")},
				"lastModified":    {S: aws.String("2020-12-09T15:32:32.362503673Z")},
				"attributes": {M: map[string]*dynamodb.AttributeValue{
					"RevisionId":   {S: aws.String("433968bb-c360-4411-8f38-0ac65767f230")},
					"LastModified": {S: aws.String("2020-12-15T11:10:32.883+0000")},
					"ResourceId":   {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"Region":       {S: aws.String("eu-west-1")},
					"Arn":          {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"ResourceType": {S: aws.String("AWS.Lambda.Function")},
					"AccountId":    {S: aws.String("123456789012")},
					"Name":         {S: aws.String("panther")},
					"Tags": {M: map[string]*dynamodb.AttributeValue{
						"key": {S: aws.String("value")},
					}}}},
			},
			OldImage: map[string]*dynamodb.AttributeValue{
				"id":            {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"lowerId":       {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"expiresAt":     {N: aws.String("1607707952")},
				"integrationId": {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				// This source was not deleted before
				"deleted":         {BOOL: aws.Bool(false)},
				"integrationType": {S: aws.String("aws")},
				"type":            {S: aws.String("AWS.Lambda.Function")},
				"lastModified":    {S: aws.String("2020-12-09T15:32:32.362503673Z")},
				"attributes": {M: map[string]*dynamodb.AttributeValue{
					"RevisionId":   {S: aws.String("433968bb-c360-4411-8f38-0ac65767f230")},
					"LastModified": {S: aws.String("2020-12-15T11:10:32.883+0000")},
					"ResourceId":   {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"Region":       {S: aws.String("eu-west-1")},
					"Arn":          {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"ResourceType": {S: aws.String("AWS.Lambda.Function")},
					"AccountId":    {S: aws.String("123456789012")},
					"Name":         {S: aws.String("panther")},
					"Tags": {M: map[string]*dynamodb.AttributeValue{
						"key": {S: aws.String("value")},
					}}}},
			},
		},
	}

	// Mock fetching of integration label
	integrations := []*models.SourceIntegrationMetadata{
		{
			IntegrationID:    "8349b647-f731-48c4-9d6b-eefff4010c14",
			IntegrationLabel: "test-label",
		},
	}
	marshaledIntegrations, err := jsoniter.Marshal(integrations)
	assert.NoError(t, err)
	lambdaMock.On("Invoke", mock.Anything).Return(&lambda.InvokeOutput{Payload: marshaledIntegrations}, nil).Once()

	// Mock firehose invocation
	firehoseMock.On("PutRecordBatchWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(&firehose.PutRecordBatchOutput{}, nil).
		Once()

	assert.NoError(t, sh.Run(context.Background(), zap.L(), &events.DynamoDBEvent{Records: []events.DynamoDBEventRecord{record}}))
	lambdaMock.AssertExpectations(t)
	firehoseMock.AssertExpectations(t)

	// Verify firehose payload
	expectedChange := ResourceChange{
		ChangeType:       "DELETED",
		IntegrationID:    "8349b647-f731-48c4-9d6b-eefff4010c14",
		IntegrationLabel: "test-label",
		LastUpdated:      "2020-12-09T15:32:32.362503673Z",
		ID:               "arn:aws:lambda:eu-west-1:123456789012:function:panther",
		Changes:          nil,
		ResourceAttributes: ResourceAttributes{
			TimeCreated:  nil,
			Name:         aws.String("panther"),
			ResourceType: aws.String("AWS.Lambda.Function"),
			ResourceID:   aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther"),
			Region:       aws.String("eu-west-1"),
			AccountID:    aws.String("123456789012"),
			ARN:          aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther"),
			Tags: map[string]string{
				"key": "value",
			},
		},
	}

	var expectedResource map[string]interface{}
	if err = dynamodbattribute.Unmarshal(record.Change.NewImage["attributes"], &expectedResource); err != nil {
		t.Error("failed to marshal attributes")
	}
	expectedChange.Resource = expectedResource

	request := firehoseMock.Calls[0].Arguments[1].(*firehose.PutRecordBatchInput)
	assert.Equal(t, 1, len(request.Records))
	assert.Equal(t, "stream-name", *request.DeliveryStreamName)
	var change ResourceChange
	if err := jsoniter.Unmarshal(request.Records[0].Data, &change); err != nil {
		t.Error("failed to unmarshal change")
	}
	assert.Equal(t, expectedChange, change)
}

func TestResourceMarkedCreated(t *testing.T) {
	t.Parallel()
	lambdaMock := &testutils.LambdaMock{}
	firehoseMock := &testutils.FirehoseMock{}

	sh := StreamHandler{
		LambdaClient:   lambdaMock,
		FirehoseClient: firehoseMock,
		StreamName:     "stream-name",
	}

	record := events.DynamoDBEventRecord{
		AWSRegion:      "eu-west-1",
		EventSource:    "aws:dynamodb",
		EventName:      "MODIFY",
		EventID:        "a04e16d70e2520ff8a3569354b55b3f5",
		EventVersion:   "1.1",
		EventSourceArn: "arn:aws:dynamodb:eu-west-1:123456789012:table/panther-resources/stream/2020-12-09T13:15:55.703",
		Change: events.DynamoDBStreamRecord{
			Keys: map[string]*dynamodb.AttributeValue{
				"id": {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
			},
			NewImage: map[string]*dynamodb.AttributeValue{
				"id":            {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"lowerId":       {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"expiresAt":     {N: aws.String("1607707952")},
				"integrationId": {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				// This source is no longer deleted
				"deleted":         {BOOL: aws.Bool(false)},
				"integrationType": {S: aws.String("aws")},
				"type":            {S: aws.String("AWS.Lambda.Function")},
				"lastModified":    {S: aws.String("2020-12-09T15:32:32.362503673Z")},
				"attributes": {M: map[string]*dynamodb.AttributeValue{
					"RevisionId":   {S: aws.String("433968bb-c360-4411-8f38-0ac65767f230")},
					"LastModified": {S: aws.String("2020-12-15T11:10:32.883+0000")},
					"ResourceId":   {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"Region":       {S: aws.String("eu-west-1")},
					"Arn":          {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"ResourceType": {S: aws.String("AWS.Lambda.Function")},
					"AccountId":    {S: aws.String("123456789012")},
					"Name":         {S: aws.String("panther")},
					"Tags": {M: map[string]*dynamodb.AttributeValue{
						"key": {S: aws.String("value")},
					}}}},
			},
			OldImage: map[string]*dynamodb.AttributeValue{
				"id":            {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"lowerId":       {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
				"expiresAt":     {N: aws.String("1607707952")},
				"integrationId": {S: aws.String("8349b647-f731-48c4-9d6b-eefff4010c14")},
				// This source was deleted
				"deleted":         {BOOL: aws.Bool(true)},
				"integrationType": {S: aws.String("aws")},
				"type":            {S: aws.String("AWS.Lambda.Function")},
				"lastModified":    {S: aws.String("2020-12-09T15:32:32.362503673Z")},
				"attributes": {M: map[string]*dynamodb.AttributeValue{
					"RevisionId":   {S: aws.String("433968bb-c360-4411-8f38-0ac65767f230")},
					"LastModified": {S: aws.String("2020-12-15T11:10:32.883+0000")},
					"ResourceId":   {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"Region":       {S: aws.String("eu-west-1")},
					"Arn":          {S: aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther")},
					"ResourceType": {S: aws.String("AWS.Lambda.Function")},
					"AccountId":    {S: aws.String("123456789012")},
					"Name":         {S: aws.String("panther")},
					"Tags": {M: map[string]*dynamodb.AttributeValue{
						"key": {S: aws.String("value")},
					}}}},
			},
		},
	}

	// Mock fetching of integration label
	integrations := []*models.SourceIntegrationMetadata{
		{
			IntegrationID:    "8349b647-f731-48c4-9d6b-eefff4010c14",
			IntegrationLabel: "test-label",
		},
	}
	marshaledIntegrations, err := jsoniter.Marshal(integrations)
	assert.NoError(t, err)
	lambdaMock.On("Invoke", mock.Anything).Return(&lambda.InvokeOutput{Payload: marshaledIntegrations}, nil).Once()

	// Mock firehose invocation
	firehoseMock.On("PutRecordBatchWithContext", mock.Anything, mock.Anything, mock.Anything).
		Return(&firehose.PutRecordBatchOutput{}, nil).
		Once()

	assert.NoError(t, sh.Run(context.Background(), zap.L(), &events.DynamoDBEvent{Records: []events.DynamoDBEventRecord{record}}))
	lambdaMock.AssertExpectations(t)
	firehoseMock.AssertExpectations(t)

	// Verify firehose payload
	expectedChange := ResourceChange{
		ChangeType:       "CREATED",
		IntegrationID:    "8349b647-f731-48c4-9d6b-eefff4010c14",
		IntegrationLabel: "test-label",
		LastUpdated:      "2020-12-09T15:32:32.362503673Z",
		ID:               "arn:aws:lambda:eu-west-1:123456789012:function:panther",
		Changes:          nil,
		ResourceAttributes: ResourceAttributes{
			TimeCreated:  nil,
			Name:         aws.String("panther"),
			ResourceType: aws.String("AWS.Lambda.Function"),
			ResourceID:   aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther"),
			Region:       aws.String("eu-west-1"),
			AccountID:    aws.String("123456789012"),
			ARN:          aws.String("arn:aws:lambda:eu-west-1:123456789012:function:panther"),
			Tags: map[string]string{
				"key": "value",
			},
		},
	}

	var expectedResource map[string]interface{}
	if err = dynamodbattribute.Unmarshal(record.Change.NewImage["attributes"], &expectedResource); err != nil {
		t.Error("failed to marshal attributes")
	}
	expectedChange.Resource = expectedResource

	request := firehoseMock.Calls[0].Arguments[1].(*firehose.PutRecordBatchInput)
	assert.Equal(t, 1, len(request.Records))
	assert.Equal(t, "stream-name", *request.DeliveryStreamName)
	var change ResourceChange
	if err := jsoniter.Unmarshal(request.Records[0].Data, &change); err != nil {
		t.Error("failed to unmarshal change")
	}
	assert.Equal(t, expectedChange, change)
}
