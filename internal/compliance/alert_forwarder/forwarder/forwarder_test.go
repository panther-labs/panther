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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/delivery/models"
	alertApiModels "github.com/panther-labs/panther/internal/log_analysis/alerts_api/models"
	"github.com/panther-labs/panther/pkg/metrics"
	"github.com/panther-labs/panther/pkg/testutils"
)

var (
	expectedMetric     = []metrics.Metric{{Name: "AlertsCreated", Value: 1, Unit: metrics.UnitCount}}
	expectedDimensions = []metrics.Dimension{
		{Name: "Severity", Value: "INFO"},
		{Name: "AnalysisType", Value: "Policy"},
		{Name: "AnalysisID", Value: "Test.Policy"}}
	timeNow = time.Unix(1581379785, 0).UTC() // Set a static time
)

func genSampleAlert() models.Alert {
	return models.Alert{
		AlertID:             aws.String("26df596024d2e81140de028387d517da"), // This is generated dynamically
		CreatedAt:           timeNow,
		Severity:            "INFO",
		Title:               "some title",
		AnalysisID:          "Test.Policy",
		AnalysisName:        aws.String("A test policy to generate alerts"),
		AnalysisDescription: "An alert triggered from a Policy...",
		AnalysisSourceID:    "9d1f16f0-8bcc-11ea-afeb-efa9a81fb878",
		Version:             aws.String("A policy version"),
		ResourceTypes:       []string{"Resource", "Types"},
		ResourceID:          "arn:aws:iam::xxx...",
		Runbook:             "Check out our docs!",
		Tags:                []string{"Tag", "Policy", "AWS"},
		Type:                models.PolicyType,
	}
}

func TestHandleStoreAndSendNotification(t *testing.T) {
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}

	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}

	expectedAlert := genSampleAlert()

	// Next, simulate sending to SQS
	expectedMarshaledAlert, err := jsoniter.MarshalToString(expectedAlert)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: &expectedMarshaledAlert,
		QueueUrl:    aws.String("queueUrl"),
	}
	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

	// Then, simulate sending to DDB
	expectedDynamoAlert := &alertApiModels.Alert{
		ID:            "26df596024d2e81140de028387d517da",
		TimePartition: "defaultPartition",
		Severity:      aws.String("INFO"),
		Title:         expectedAlert.Title,
		AlertPolicy: alertApiModels.AlertPolicy{
			PolicyID:          expectedAlert.AnalysisID,
			PolicyDisplayName: aws.StringValue(expectedAlert.AnalysisName),
			PolicyVersion:     aws.StringValue(expectedAlert.Version),
			PolicySourceID:    expectedAlert.AnalysisSourceID,
			ResourceTypes:     expectedAlert.ResourceTypes,
			ResourceID:        expectedAlert.ResourceID,
		},
		// Reuse part of the struct that was intended for Rules
		AlertDedupEvent: alertApiModels.AlertDedupEvent{
			RuleID:       expectedAlert.AnalysisID, // Required for DDB GSI constraint
			CreationTime: expectedAlert.CreatedAt,
			UpdateTime:   expectedAlert.CreatedAt,
			Type:         expectedAlert.Type,
		},
	}
	expectedMarshaledDynamoAlert, err := dynamodbattribute.MarshalMap(expectedDynamoAlert)
	assert.NoError(t, err)
	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledDynamoAlert,
		TableName: aws.String("alertsTable"),
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	metricsMock.On("Log", expectedDimensions, expectedMetric).Once()
	assert.NoError(t, handler.Do(expectedAlert))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}
