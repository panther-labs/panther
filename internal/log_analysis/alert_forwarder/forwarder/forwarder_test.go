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
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	ruleModel "github.com/panther-labs/panther/api/lambda/analysis/models"
	alertModel "github.com/panther-labs/panther/api/lambda/delivery/models"
	alertApiModels "github.com/panther-labs/panther/internal/log_analysis/alerts_api/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
	"github.com/panther-labs/panther/pkg/metrics"
	"github.com/panther-labs/panther/pkg/testutils"
)

var (
	oldAlertDedupEvent = &alertApiModels.AlertDedupEvent{
		RuleID:              "ruleId",
		RuleVersion:         "ruleVersion",
		DeduplicationString: "dedupString",
		Type:                alertModel.RuleType,
		AlertCount:          10,
		CreationTime:        time.Now().UTC(),
		UpdateTime:          time.Now().UTC().Add(1 * time.Minute),
		EventCount:          100,
		LogTypes:            []string{"Log.Type.1", "Log.Type.2"},
		GeneratedTitle:      aws.String("test title"),
	}

	newAlertDedupEvent = &alertApiModels.AlertDedupEvent{
		RuleID:              oldAlertDedupEvent.RuleID,
		RuleVersion:         oldAlertDedupEvent.RuleVersion,
		DeduplicationString: oldAlertDedupEvent.DeduplicationString,
		Type:                oldAlertDedupEvent.Type,
		AlertCount:          oldAlertDedupEvent.AlertCount + 1,
		CreationTime:        time.Now().UTC(),
		UpdateTime:          time.Now().UTC().Add(1 * time.Minute),
		EventCount:          oldAlertDedupEvent.EventCount,
		LogTypes:            oldAlertDedupEvent.LogTypes,
		GeneratedTitle:      oldAlertDedupEvent.GeneratedTitle,
	}

	testRuleResponse = &ruleModel.Rule{
		Description: "Description",
		DisplayName: "DisplayName",
		ID:          "ruleId",
		Runbook:     "Runbook",
		Severity:    "INFO",
		Tags:        []string{"Tag"},
	}

	expectedGetRuleInput = &ruleModel.LambdaInput{
		GetRule: &ruleModel.GetRuleInput{
			ID:        oldAlertDedupEvent.RuleID,
			VersionID: oldAlertDedupEvent.RuleVersion,
		},
	}
	expectedMetric     = []metrics.Metric{{Name: "AlertsCreated", Value: 1, Unit: metrics.UnitCount}}
	expectedDimensions = []metrics.Dimension{
		{Name: "Severity", Value: "INFO"},
		{Name: "AnalysisType", Value: "Rule"},
		{Name: "AnalysisID", Value: "ruleId"}}
)

func TestHandleStoreAndSendNotification(t *testing.T) {
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}
	analysisMock := &gatewayapi.MockClient{}

	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		Cache:            NewCache(analysisMock),
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}

	expectedAlertNotification := &alertModel.Alert{
		CreatedAt:           newAlertDedupEvent.UpdateTime,
		AnalysisDescription: testRuleResponse.Description,
		AnalysisID:          newAlertDedupEvent.RuleID,
		Version:             &newAlertDedupEvent.RuleVersion,
		AnalysisName:        &testRuleResponse.DisplayName,
		Runbook:             testRuleResponse.Runbook,
		Severity:            string(testRuleResponse.Severity),
		Tags:                []string{"Tag"},
		Type:                alertModel.RuleType,
		AlertID:             aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
		Title:               *newAlertDedupEvent.GeneratedTitle,
	}
	expectedMarshaledAlertNotification, err := jsoniter.MarshalToString(expectedAlertNotification)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: &expectedMarshaledAlertNotification,
		QueueUrl:    aws.String("queueUrl"),
	}

	analysisMock.On("Invoke", expectedGetRuleInput, &ruleModel.Rule{}).Return(
		http.StatusOK, nil, testRuleResponse).Once()

	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

	expectedAlert := &alertApiModels.Alert{
		ID:                  "b25dc23fb2a0b362da8428dbec1381a8",
		TimePartition:       "defaultPartition",
		Severity:            aws.String(string(testRuleResponse.Severity)),
		RuleDisplayName:     &testRuleResponse.DisplayName,
		Title:               aws.StringValue(newAlertDedupEvent.GeneratedTitle),
		FirstEventMatchTime: newAlertDedupEvent.CreationTime,
		LogTypes:            newAlertDedupEvent.LogTypes,
		AlertDedupEvent: alertApiModels.AlertDedupEvent{
			RuleID:                newAlertDedupEvent.RuleID,
			Type:                  newAlertDedupEvent.Type,
			RuleVersion:           newAlertDedupEvent.RuleVersion,
			LogTypes:              newAlertDedupEvent.LogTypes,
			EventCount:            newAlertDedupEvent.EventCount,
			AlertCount:            newAlertDedupEvent.AlertCount,
			DeduplicationString:   newAlertDedupEvent.DeduplicationString,
			GeneratedTitle:        newAlertDedupEvent.GeneratedTitle,
			GeneratedDescription:  aws.String(getDescription(testRuleResponse, newAlertDedupEvent)),
			GeneratedRunbook:      aws.String(getRunbook(testRuleResponse, newAlertDedupEvent)),
			GeneratedDestinations: newAlertDedupEvent.GeneratedDestinations,
			UpdateTime:            newAlertDedupEvent.UpdateTime,
			CreationTime:          newAlertDedupEvent.UpdateTime,
		},
	}

	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
	assert.NoError(t, err)

	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledAlert,
		TableName: aws.String("alertsTable"),
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	metricsMock.On("Log", expectedDimensions, expectedMetric).Once()
	assert.NoError(t, handler.Do(oldAlertDedupEvent, newAlertDedupEvent))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	analysisMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}

func TestHandleStoreAndSendNotificationNoRuleDisplayNameNoTitle(t *testing.T) {
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}
	analysisMock := &gatewayapi.MockClient{}

	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		Cache:            NewCache(analysisMock),
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}

	newAlertDedupEventWithoutTitle := &alertApiModels.AlertDedupEvent{
		RuleID:              oldAlertDedupEvent.RuleID,
		RuleVersion:         oldAlertDedupEvent.RuleVersion,
		DeduplicationString: oldAlertDedupEvent.DeduplicationString,
		AlertCount:          oldAlertDedupEvent.AlertCount + 1,
		CreationTime:        time.Now().UTC(),
		UpdateTime:          time.Now().UTC().Add(1 * time.Minute),
		EventCount:          oldAlertDedupEvent.EventCount,
		LogTypes:            oldAlertDedupEvent.LogTypes,
		Type:                oldAlertDedupEvent.Type,
	}

	expectedAlertNotification := &alertModel.Alert{
		CreatedAt:           newAlertDedupEventWithoutTitle.UpdateTime,
		AnalysisDescription: testRuleResponse.Description,
		AnalysisID:          newAlertDedupEventWithoutTitle.RuleID,
		Version:             &newAlertDedupEventWithoutTitle.RuleVersion,
		Runbook:             testRuleResponse.Runbook,
		Severity:            string(testRuleResponse.Severity),
		Tags:                []string{"Tag"},
		Type:                alertModel.RuleType,
		AlertID:             aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
		Title:               newAlertDedupEventWithoutTitle.RuleID,
	}
	expectedMarshaledAlertNotification, err := jsoniter.MarshalToString(expectedAlertNotification)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: aws.String(expectedMarshaledAlertNotification),
		QueueUrl:    aws.String("queueUrl"),
	}

	testRuleResponseWithoutDisplayName := &ruleModel.Rule{
		Description: "Description",
		ID:          "ruleId",
		Runbook:     "Runbook",
		Severity:    "INFO",
		Tags:        []string{"Tag"},
	}

	analysisMock.On("Invoke", expectedGetRuleInput, &ruleModel.Rule{}).Return(
		http.StatusOK, nil, testRuleResponseWithoutDisplayName).Once()

	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

	expectedAlert := &alertApiModels.Alert{
		ID:                  "b25dc23fb2a0b362da8428dbec1381a8",
		TimePartition:       "defaultPartition",
		Severity:            aws.String(string(testRuleResponse.Severity)),
		Title:               newAlertDedupEventWithoutTitle.RuleID,
		FirstEventMatchTime: newAlertDedupEventWithoutTitle.CreationTime,
		LogTypes:            newAlertDedupEvent.LogTypes,
		AlertDedupEvent: alertApiModels.AlertDedupEvent{
			RuleID:                newAlertDedupEventWithoutTitle.RuleID,
			RuleVersion:           newAlertDedupEventWithoutTitle.RuleVersion,
			LogTypes:              newAlertDedupEventWithoutTitle.LogTypes,
			EventCount:            newAlertDedupEventWithoutTitle.EventCount,
			AlertCount:            newAlertDedupEventWithoutTitle.AlertCount,
			DeduplicationString:   newAlertDedupEventWithoutTitle.DeduplicationString,
			GeneratedTitle:        newAlertDedupEventWithoutTitle.GeneratedTitle,
			GeneratedDescription:  aws.String(getDescription(testRuleResponse, newAlertDedupEvent)),
			GeneratedReference:    aws.String(getReference(testRuleResponse, newAlertDedupEvent)),
			GeneratedRunbook:      aws.String(getRunbook(testRuleResponse, newAlertDedupEvent)),
			GeneratedDestinations: newAlertDedupEvent.GeneratedDestinations,
			UpdateTime:            newAlertDedupEventWithoutTitle.UpdateTime,
			CreationTime:          newAlertDedupEventWithoutTitle.UpdateTime,
			Type:                  newAlertDedupEventWithoutTitle.Type,
		},
	}

	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
	assert.NoError(t, err)

	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledAlert,
		TableName: aws.String("alertsTable"),
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	metricsMock.On("Log", expectedDimensions, expectedMetric).Once()

	assert.NoError(t, handler.Do(oldAlertDedupEvent, newAlertDedupEventWithoutTitle))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	analysisMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}

func TestHandleStoreAndSendNotificationNoGeneratedTitle(t *testing.T) {
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}
	analysisMock := &gatewayapi.MockClient{}

	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		Cache:            NewCache(analysisMock),
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}

	expectedAlertNotification := &alertModel.Alert{
		CreatedAt:           newAlertDedupEvent.UpdateTime,
		AnalysisDescription: testRuleResponse.Description,
		AnalysisID:          newAlertDedupEvent.RuleID,
		Version:             &newAlertDedupEvent.RuleVersion,
		AnalysisName:        &testRuleResponse.DisplayName,
		Runbook:             testRuleResponse.Runbook,
		Severity:            string(testRuleResponse.Severity),
		Tags:                []string{"Tag"},
		Type:                newAlertDedupEvent.Type,
		AlertID:             aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
		Title:               "DisplayName",
	}
	expectedMarshaledAlertNotification, err := jsoniter.MarshalToString(expectedAlertNotification)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: aws.String(expectedMarshaledAlertNotification),
		QueueUrl:    aws.String("queueUrl"),
	}

	analysisMock.On("Invoke", expectedGetRuleInput, &ruleModel.Rule{}).Return(
		http.StatusOK, nil, testRuleResponse).Once()
	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

	expectedAlert := &alertApiModels.Alert{
		ID:                  "b25dc23fb2a0b362da8428dbec1381a8",
		TimePartition:       "defaultPartition",
		Severity:            aws.String(string(testRuleResponse.Severity)),
		RuleDisplayName:     &testRuleResponse.DisplayName,
		Title:               "DisplayName",
		FirstEventMatchTime: newAlertDedupEvent.CreationTime,
		LogTypes:            newAlertDedupEvent.LogTypes,
		AlertDedupEvent: alertApiModels.AlertDedupEvent{
			RuleID:                newAlertDedupEvent.RuleID,
			RuleVersion:           newAlertDedupEvent.RuleVersion,
			LogTypes:              newAlertDedupEvent.LogTypes,
			Type:                  newAlertDedupEvent.Type,
			EventCount:            newAlertDedupEvent.EventCount,
			AlertCount:            newAlertDedupEvent.AlertCount,
			DeduplicationString:   newAlertDedupEvent.DeduplicationString,
			GeneratedTitle:        newAlertDedupEvent.GeneratedTitle,
			GeneratedDescription:  aws.String(getDescription(testRuleResponse, newAlertDedupEvent)),
			GeneratedRunbook:      aws.String(getRunbook(testRuleResponse, newAlertDedupEvent)),
			GeneratedDestinations: newAlertDedupEvent.GeneratedDestinations,
			UpdateTime:            newAlertDedupEvent.UpdateTime,
			CreationTime:          newAlertDedupEvent.UpdateTime,
		},
	}

	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
	assert.NoError(t, err)

	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledAlert,
		TableName: aws.String("alertsTable"),
	}

	dedupEventWithoutTitle := &alertApiModels.AlertDedupEvent{
		RuleID:              newAlertDedupEvent.RuleID,
		RuleVersion:         newAlertDedupEvent.RuleVersion,
		Type:                newAlertDedupEvent.Type,
		DeduplicationString: newAlertDedupEvent.DeduplicationString,
		AlertCount:          newAlertDedupEvent.AlertCount,
		CreationTime:        newAlertDedupEvent.CreationTime,
		UpdateTime:          newAlertDedupEvent.UpdateTime,
		EventCount:          newAlertDedupEvent.EventCount,
		LogTypes:            newAlertDedupEvent.LogTypes,
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	metricsMock.On("Log", expectedDimensions, expectedMetric).Once()

	assert.NoError(t, handler.Do(oldAlertDedupEvent, dedupEventWithoutTitle))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	analysisMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}

func TestHandleStoreAndSendNotificationNilOldDedup(t *testing.T) {
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}
	analysisMock := &gatewayapi.MockClient{}

	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		Cache:            NewCache(analysisMock),
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}

	expectedAlertNotification := &alertModel.Alert{
		CreatedAt:           newAlertDedupEvent.UpdateTime,
		AnalysisDescription: testRuleResponse.Description,
		AnalysisID:          newAlertDedupEvent.RuleID,
		AnalysisName:        &testRuleResponse.DisplayName,
		Version:             &newAlertDedupEvent.RuleVersion,
		Runbook:             testRuleResponse.Runbook,
		Severity:            string(testRuleResponse.Severity),
		Tags:                []string{"Tag"},
		Type:                alertModel.RuleType,
		AlertID:             aws.String("b25dc23fb2a0b362da8428dbec1381a8"),
		Title:               *newAlertDedupEvent.GeneratedTitle,
	}
	expectedMarshaledAlertNotification, err := jsoniter.MarshalToString(expectedAlertNotification)
	require.NoError(t, err)
	expectedSendMessageInput := &sqs.SendMessageInput{
		MessageBody: aws.String(expectedMarshaledAlertNotification),
		QueueUrl:    aws.String("queueUrl"),
	}

	analysisMock.On("Invoke", expectedGetRuleInput, &ruleModel.Rule{}).Return(
		http.StatusOK, nil, testRuleResponse).Once()

	sqsMock.On("SendMessage", expectedSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)

	expectedAlert := &alertApiModels.Alert{
		ID:                  "b25dc23fb2a0b362da8428dbec1381a8",
		TimePartition:       "defaultPartition",
		Severity:            aws.String(string(testRuleResponse.Severity)),
		Title:               aws.StringValue(newAlertDedupEvent.GeneratedTitle),
		RuleDisplayName:     &testRuleResponse.DisplayName,
		FirstEventMatchTime: newAlertDedupEvent.CreationTime,
		LogTypes:            newAlertDedupEvent.LogTypes,
		AlertDedupEvent: alertApiModels.AlertDedupEvent{
			RuleID:                newAlertDedupEvent.RuleID,
			Type:                  newAlertDedupEvent.Type,
			RuleVersion:           newAlertDedupEvent.RuleVersion,
			LogTypes:              newAlertDedupEvent.LogTypes,
			EventCount:            newAlertDedupEvent.EventCount,
			AlertCount:            newAlertDedupEvent.AlertCount,
			DeduplicationString:   newAlertDedupEvent.DeduplicationString,
			GeneratedTitle:        newAlertDedupEvent.GeneratedTitle,
			GeneratedDescription:  aws.String(getDescription(testRuleResponse, newAlertDedupEvent)),
			GeneratedRunbook:      aws.String(getRunbook(testRuleResponse, newAlertDedupEvent)),
			GeneratedDestinations: newAlertDedupEvent.GeneratedDestinations,
			UpdateTime:            newAlertDedupEvent.UpdateTime,
			CreationTime:          newAlertDedupEvent.UpdateTime,
		},
	}

	expectedMarshaledAlert, err := dynamodbattribute.MarshalMap(expectedAlert)
	require.NoError(t, err)

	expectedPutItemRequest := &dynamodb.PutItemInput{
		Item:      expectedMarshaledAlert,
		TableName: aws.String("alertsTable"),
	}

	ddbMock.On("PutItem", expectedPutItemRequest).Return(&dynamodb.PutItemOutput{}, nil)
	metricsMock.On("Log", expectedDimensions, expectedMetric).Once()

	require.NoError(t, handler.Do(nil, newAlertDedupEvent))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	analysisMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}

func TestHandleUpdateAlert(t *testing.T) {
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}
	analysisMock := &gatewayapi.MockClient{}

	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		Cache:            NewCache(analysisMock),
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}
	analysisMock.On("Invoke", expectedGetRuleInput, &ruleModel.Rule{}).Return(
		http.StatusOK, nil, testRuleResponse).Once()

	dedupEventWithUpdatedFields := &alertApiModels.AlertDedupEvent{
		RuleID:                newAlertDedupEvent.RuleID,
		RuleVersion:           newAlertDedupEvent.RuleVersion,
		DeduplicationString:   newAlertDedupEvent.DeduplicationString,
		AlertCount:            newAlertDedupEvent.AlertCount,
		CreationTime:          newAlertDedupEvent.CreationTime,
		UpdateTime:            newAlertDedupEvent.UpdateTime.Add(1 * time.Minute),
		EventCount:            newAlertDedupEvent.EventCount + 10,
		LogTypes:              append(newAlertDedupEvent.LogTypes, "New.Log.Type"),
		GeneratedTitle:        newAlertDedupEvent.GeneratedTitle,
		GeneratedDescription:  newAlertDedupEvent.GeneratedDescription,
		GeneratedRunbook:      newAlertDedupEvent.GeneratedRunbook,
		GeneratedDestinations: newAlertDedupEvent.GeneratedDestinations,
	}

	updateExpression := expression.
		Set(expression.Name("eventCount"), expression.Value(aws.Int64(dedupEventWithUpdatedFields.EventCount))).
		Set(expression.Name("logTypes"), expression.Value(aws.StringSlice(dedupEventWithUpdatedFields.LogTypes))).
		Set(expression.Name("updateTime"), expression.Value(aws.Time(dedupEventWithUpdatedFields.UpdateTime)))
	expr, err := expression.NewBuilder().WithUpdate(updateExpression).Build()
	require.NoError(t, err)

	expectedUpdateItemInput := &dynamodb.UpdateItemInput{
		TableName: aws.String("alertsTable"),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {S: aws.String("b25dc23fb2a0b362da8428dbec1381a8")},
		},
		UpdateExpression:          expr.Update(),
		ExpressionAttributeValues: expr.Values(),
		ExpressionAttributeNames:  expr.Names(),
	}

	ddbMock.On("UpdateItem", expectedUpdateItemInput).Return(&dynamodb.UpdateItemOutput{}, nil)
	// We shouldn't log any metric - we are not creating a new Alert
	metricsMock.AssertNotCalled(t, "Log")

	assert.NoError(t, handler.Do(newAlertDedupEvent, dedupEventWithUpdatedFields))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	analysisMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}

func TestHandleUpdateAlertDDBError(t *testing.T) {
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}
	analysisMock := &gatewayapi.MockClient{}
	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		Cache:            NewCache(analysisMock),
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}
	analysisMock.On("Invoke", expectedGetRuleInput, &ruleModel.Rule{}).Return(
		http.StatusOK, nil, testRuleResponse).Once()
	dedupEventWithUpdatedFields := &alertApiModels.AlertDedupEvent{
		RuleID:                newAlertDedupEvent.RuleID,
		RuleVersion:           newAlertDedupEvent.RuleVersion,
		DeduplicationString:   newAlertDedupEvent.DeduplicationString,
		AlertCount:            newAlertDedupEvent.AlertCount,
		CreationTime:          newAlertDedupEvent.CreationTime,
		UpdateTime:            newAlertDedupEvent.UpdateTime.Add(1 * time.Minute),
		EventCount:            newAlertDedupEvent.EventCount + 10,
		LogTypes:              append(newAlertDedupEvent.LogTypes, "New.Log.Type"),
		GeneratedTitle:        newAlertDedupEvent.GeneratedTitle,
		GeneratedDescription:  newAlertDedupEvent.GeneratedDescription,
		GeneratedRunbook:      newAlertDedupEvent.GeneratedRunbook,
		GeneratedDestinations: newAlertDedupEvent.GeneratedDestinations,
	}

	ddbMock.On("UpdateItem", mock.Anything).Return(&dynamodb.UpdateItemOutput{}, errors.New("error"))
	assert.Error(t, handler.Do(newAlertDedupEvent, dedupEventWithUpdatedFields))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	analysisMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}

func TestHandleShouldNotCreateOrUpdateAlertIfThresholdNotReached(t *testing.T) {
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}
	analysisMock := &gatewayapi.MockClient{}
	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		Cache:            NewCache(analysisMock),
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}

	ruleWithThreshold := &ruleModel.Rule{
		ID:          "ruleId",
		Description: "Description",
		DisplayName: "DisplayName",
		Runbook:     "Runbook",
		Severity:    "INFO",
		Tags:        []string{"Tag"},
		Threshold:   1000,
	}

	analysisMock.On("Invoke", expectedGetRuleInput, &ruleModel.Rule{}).Return(
		http.StatusOK, nil, ruleWithThreshold).Once()
	assert.NoError(t, handler.Do(oldAlertDedupEvent, newAlertDedupEvent))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	analysisMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}

func TestHandleDontConsiderThresholdInRuleErrors(t *testing.T) {
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}
	analysisMock := &gatewayapi.MockClient{}
	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		Cache:            NewCache(analysisMock),
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}

	ruleWithThreshold := &ruleModel.Rule{
		ID:          "ruleId",
		Description: "Description",
		DisplayName: "DisplayName",
		Runbook:     "Runbook",
		Severity:    "INFO",
		Tags:        []string{"Tag"},
		Threshold:   1000,
	}

	ruleErrorDedup := *newAlertDedupEvent
	ruleErrorDedup.Type = alertModel.RuleErrorType

	analysisMock.On("Invoke", expectedGetRuleInput, &ruleModel.Rule{}).Return(
		http.StatusOK, nil, ruleWithThreshold).Once()

	ddbMock.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, nil)
	sqsMock.On("SendMessage", mock.Anything).Return(&sqs.SendMessageOutput{}, nil)
	assert.NoError(t, handler.Do(nil, &ruleErrorDedup))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	analysisMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}

func TestHandleShouldCreateAlertIfThresholdNowReached(t *testing.T) {
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}
	analysisMock := &gatewayapi.MockClient{}
	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		Cache:            NewCache(analysisMock),
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}

	ruleWithThreshold := &ruleModel.Rule{
		ID:          "ruleId",
		Description: "Description",
		DisplayName: "DisplayName",
		Runbook:     "Runbook",
		Severity:    "INFO",
		Tags:        []string{"Tag"},
		Threshold:   1000,
	}

	newAlertDedup := &alertApiModels.AlertDedupEvent{
		RuleID:                oldAlertDedupEvent.RuleID,
		Type:                  oldAlertDedupEvent.Type,
		RuleVersion:           oldAlertDedupEvent.RuleVersion,
		DeduplicationString:   oldAlertDedupEvent.DeduplicationString,
		AlertCount:            oldAlertDedupEvent.AlertCount + 1,
		CreationTime:          time.Now().UTC(),
		UpdateTime:            time.Now().UTC(),
		EventCount:            1001,
		LogTypes:              oldAlertDedupEvent.LogTypes,
		GeneratedTitle:        oldAlertDedupEvent.GeneratedTitle,
		GeneratedDescription:  newAlertDedupEvent.GeneratedDescription,
		GeneratedReference:    newAlertDedupEvent.GeneratedReference,
		GeneratedRunbook:      newAlertDedupEvent.GeneratedRunbook,
		GeneratedDestinations: newAlertDedupEvent.GeneratedDestinations,
	}

	ddbMock.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, nil).Once()
	sqsMock.On("SendMessage", mock.Anything).Return(&sqs.SendMessageOutput{}, nil).Once()
	metricsMock.On("Log", expectedDimensions, expectedMetric).Once()

	analysisMock.On("Invoke", expectedGetRuleInput, &ruleModel.Rule{}).Return(
		http.StatusOK, nil, ruleWithThreshold).Once()
	assert.NoError(t, handler.Do(oldAlertDedupEvent, newAlertDedup))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	analysisMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}

func TestHandleError(t *testing.T) {
	// In case of an RULE_ERROR alert type, behave the same
	// but don't log Severity metric
	t.Parallel()
	ddbMock := &testutils.DynamoDBMock{}
	sqsMock := &testutils.SqsMock{}
	metricsMock := &testutils.LoggerMock{}
	analysisMock := &gatewayapi.MockClient{}
	handler := &Handler{
		AlertTable:       "alertsTable",
		AlertingQueueURL: "queueUrl",
		Cache:            NewCache(analysisMock),
		DdbClient:        ddbMock,
		SqsClient:        sqsMock,
		MetricsLogger:    metricsMock,
	}

	analysisMock.On("Invoke", expectedGetRuleInput, &ruleModel.Rule{}).Return(
		http.StatusOK, nil, testRuleResponse).Once()
	sqsMock.On("SendMessage", mock.Anything).Return(&sqs.SendMessageOutput{}, nil)
	ddbMock.On("PutItem", mock.Anything).Return(&dynamodb.PutItemOutput{}, nil)
	metricsMock.AssertNotCalled(t, "LogSingle")

	oldErrorDedupEvent := *oldAlertDedupEvent
	newErrorDedupEvent := *newAlertDedupEvent
	oldErrorDedupEvent.Type = "RULE_ERROR"
	newErrorDedupEvent.Type = "RULE_ERROR"
	assert.NoError(t, handler.Do(&oldErrorDedupEvent, &newErrorDedupEvent))

	ddbMock.AssertExpectations(t)
	sqsMock.AssertExpectations(t)
	analysisMock.AssertExpectations(t)
	metricsMock.AssertExpectations(t)
}
