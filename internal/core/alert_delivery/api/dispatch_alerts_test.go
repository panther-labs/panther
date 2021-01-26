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
	"github.com/aws/aws-sdk-go/service/lambda"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestGetAlerts(t *testing.T) {
	alertID := aws.String("alert-id")
	outputIds := []string{
		"424ccb6b-0e43-4fd3-9c8b-3862a5f0f4c2",
		"424ccb6b-0e43-4fd3-9c8b-3862a5f0f4c3",
		"424ccb6b-0e43-4fd3-9c8b-3862a5f0f4c3",
	}

	alert := &deliverymodel.Alert{
		AlertID:             alertID,
		AnalysisDescription: "A test alert",
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             "A runbook link",
		Title:               "Test Alert",
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliverymodel.RuleType,
		OutputIds:           outputIds,
		Severity:            "INFO",
		CreatedAt:           time.Now().UTC(),
		Version:             aws.String("abc"),
	}
	bodyBytes, err := jsoniter.Marshal(alert)
	require.NoError(t, err)
	bodyString := string(bodyBytes)
	input := []*deliverymodel.DispatchAlertsInput{
		{
			MessageId:     "messageId",
			ReceiptHandle: "MessageReceiptHandle",
			Body:          bodyString,
			Md5OfBody:     "7b270e59b47ff90a553787216d55d91d",
			Attributes: map[string]string{
				"ApproximateReceiveCount":          "1",
				"SentTimestamp":                    "1523232000000",
				"SenderId":                         "123456789012",
				"ApproximateFirstReceiveTimestamp": "1523232000001",
			},
			EventSourceARN: "arn:aws:sqs:us-west-2:123456789012:MyQueue",
			EventSource:    "aws:sqs",
			AWSRegion:      "us-west-2",
		},
	}
	expectedResult := []*deliverymodel.Alert{alert}
	result := getAlerts(input)

	assert.Equal(t, expectedResult, result)
}

func TestGetAlertOutputMap(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient

	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alerts := []*deliverymodel.Alert{
		{
			AlertID:             alertID,
			AnalysisDescription: "A test alert",
			AnalysisID:          "Test.Analysis.ID",
			AnalysisName:        aws.String("Test Analysis Name"),
			Runbook:             "A runbook link",
			Title:               "Test Alert",
			RetryCount:          0,
			Tags:                []string{"test", "alert"},
			Type:                deliverymodel.RuleType,
			OutputIds:           outputIds,
			Severity:            "INFO",
			CreatedAt:           time.Now().UTC(),
			Version:             aws.String("abc"),
		},
	}

	outputs := []*outputModels.AlertOutput{
		{
			OutputID:           aws.String(outputIds[0]),
			OutputType:         aws.String("slack"),
			DefaultForSeverity: []*string{aws.String("INFO")},
			AlertTypes:         []string{deliverymodel.RuleType},
		},
		{
			OutputID:           aws.String(outputIds[1]),
			OutputType:         aws.String("customwebhook"),
			AlertTypes:         []string{deliverymodel.RuleType},
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM")},
		},
		{
			OutputID:           aws.String(outputIds[2]),
			OutputType:         aws.String("asana"),
			AlertTypes:         []string{deliverymodel.RuleType},
			DefaultForSeverity: []*string{aws.String("INFO"), aws.String("MEDIUM"), aws.String("CRITICAL")},
		},
	}

	payload, err := jsoniter.Marshal(outputs)
	require.NoError(t, err)
	mockLambdaResponse := &lambda.InvokeOutput{Payload: payload}
	mockClient.On("Invoke", mock.Anything).Return(mockLambdaResponse, nil).Once()

	// AlertOutputMap map[*deliverymodel.Alert][]*outputModels.AlertOutput
	expectedResult := AlertOutputMap{
		alerts[0]: outputs,
	}

	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	result, err := getAlertOutputMap(alerts)
	require.NoError(t, err)

	assert.Equal(t, len(expectedResult[alerts[0]]), len(result[alerts[0]]))

	equalCount := 0
	for _, expOutput := range expectedResult[alerts[0]] {
		for _, output := range result[alerts[0]] {
			if *expOutput.OutputID == *output.OutputID {
				assert.Equal(t, expOutput, output)
				equalCount++
			}
		}
	}
	assert.Equal(t, 3, equalCount)
}

func TestGetAlertOutputMapError(t *testing.T) {
	mockClient := &testutils.LambdaMock{}
	lambdaClient = mockClient

	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alerts := []*deliverymodel.Alert{
		{
			AlertID:             alertID,
			AnalysisDescription: "A test alert",
			AnalysisID:          "Test.Analysis.ID",
			AnalysisName:        aws.String("Test Analysis Name"),
			Runbook:             "A runbook link",
			Title:               "Test Alert",
			RetryCount:          0,
			Tags:                []string{"test", "alert"},
			Type:                deliverymodel.RuleType,
			OutputIds:           outputIds,
			Severity:            "INFO",
			CreatedAt:           time.Now().UTC(),
			Version:             aws.String("abc"),
		},
	}

	mockClient.On("Invoke", mock.Anything).Return((*lambda.InvokeOutput)(nil), errors.New("error")).Once()

	// AlertOutputMap map[*deliverymodel.Alert][]*outputModels.AlertOutput
	expectedResult := AlertOutputMap{}

	// Need to expire the cache because other tests mutate this global when run in parallel
	outputsCache = &alertOutputsCache{
		RefreshInterval: time.Second * time.Duration(30),
		Expiry:          time.Now().Add(time.Minute * time.Duration(-5)),
	}
	result, err := getAlertOutputMap(alerts)
	require.Error(t, err)

	assert.Equal(t, expectedResult, result)
}

func TestFilterDispatches(t *testing.T) {
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}
	dispatchedAt := time.Now().UTC()

	successStatuses := []DispatchStatus{
		{
			Alert:        deliverymodel.Alert{},
			OutputID:     outputIds[0],
			Message:      "success",
			StatusCode:   200,
			Success:      true,
			NeedsRetry:   false,
			DispatchedAt: dispatchedAt,
		},
	}
	failedStatuses := []DispatchStatus{
		{
			Alert:        deliverymodel.Alert{},
			OutputID:     outputIds[1],
			Message:      "failure",
			StatusCode:   401,
			Success:      false,
			NeedsRetry:   true,
			DispatchedAt: dispatchedAt,
		},
		{
			Alert:        deliverymodel.Alert{},
			OutputID:     outputIds[2],
			Message:      "failure",
			StatusCode:   500,
			Success:      false,
			NeedsRetry:   false,
			DispatchedAt: dispatchedAt,
		},
	}

	statuses := []DispatchStatus{}
	statuses = append(statuses, successStatuses...)
	statuses = append(statuses, failedStatuses...)

	resultSuccess, resultFailed := filterDispatches(statuses)
	assert.Equal(t, successStatuses, resultSuccess)
	assert.Equal(t, failedStatuses, resultFailed)
}

func TestGetAlertsToRetry(t *testing.T) {
	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}
	createdAt := time.Now().UTC()
	dispatchedAt := time.Now().UTC()
	alerts := []*deliverymodel.Alert{
		// Needs to be retried
		{
			AlertID:             alertID,
			AnalysisDescription: "A test alert",
			AnalysisID:          "Test.Analysis.ID",
			AnalysisName:        aws.String("Test Analysis Name"),
			Runbook:             "A runbook link",
			Title:               "Test Alert",
			RetryCount:          0,
			Tags:                []string{"test", "alert"},
			Type:                deliverymodel.RuleType,
			OutputIds:           outputIds,
			Severity:            "INFO",
			CreatedAt:           createdAt,
			Version:             aws.String("abc"),
		},
		// Should be ignored because it has exceeded the max retry count
		{
			AlertID:             alertID,
			AnalysisDescription: "A test alert",
			AnalysisID:          "Test.Analysis.ID",
			AnalysisName:        aws.String("Test Analysis Name"),
			Runbook:             "A runbook link",
			Title:               "Test Alert",
			RetryCount:          10,
			Tags:                []string{"test", "alert"},
			Type:                deliverymodel.RuleType,
			OutputIds:           outputIds,
			Severity:            "INFO",
			CreatedAt:           createdAt,
			Version:             aws.String("abc"),
		},
	}

	failedStatuses := []DispatchStatus{
		// [TRUE] Status says to retry (true), alert says to retry (true)
		{
			Alert:        *alerts[0],
			OutputID:     outputIds[0],
			Message:      "failure",
			StatusCode:   401,
			Success:      false,
			NeedsRetry:   true,
			DispatchedAt: dispatchedAt,
		},
		// [FALSE] Should not be retried because of permanent failure, alert says to retry (true)
		{
			Alert:        *alerts[0],
			OutputID:     outputIds[1],
			Message:      "failure",
			StatusCode:   500,
			Success:      false,
			NeedsRetry:   false,
			DispatchedAt: dispatchedAt,
		},
		// [FALSE] Should not be retried because this is marked a success, alert says to retry (true)
		{
			Alert:        *alerts[0],
			OutputID:     outputIds[1],
			Message:      "success",
			StatusCode:   200,
			Success:      true,
			NeedsRetry:   false,
			DispatchedAt: dispatchedAt,
		},

		// [FALSE] Should be retried, alert exceeded max retries (false)
		{
			Alert:        *alerts[1],
			OutputID:     outputIds[0],
			Message:      "failure",
			StatusCode:   401,
			Success:      false,
			NeedsRetry:   true,
			DispatchedAt: dispatchedAt,
		},
		// [FALSE] Should not be retried because of permanent failure, alert exceeded max retries (false)
		{
			Alert:        *alerts[1],
			OutputID:     outputIds[1],
			Message:      "failure",
			StatusCode:   500,
			Success:      false,
			NeedsRetry:   false,
			DispatchedAt: dispatchedAt,
		},
		// [FALSE] Should not be retried because this is marked a success, alert exceeded max retries (false)
		{
			Alert:        *alerts[1],
			OutputID:     outputIds[1],
			Message:      "success",
			StatusCode:   200,
			Success:      true,
			NeedsRetry:   false,
			DispatchedAt: dispatchedAt,
		},
	}

	// The expected result will have an incremented retry count and the outputIds set to the single output which has failed
	expectedResult := []*deliverymodel.Alert{
		{
			AlertID:             alertID,
			AnalysisDescription: "A test alert",
			AnalysisID:          "Test.Analysis.ID",
			AnalysisName:        aws.String("Test Analysis Name"),
			Runbook:             "A runbook link",
			Title:               "Test Alert",
			RetryCount:          1,
			Tags:                []string{"test", "alert"},
			Type:                deliverymodel.RuleType,
			OutputIds:           []string{outputIds[0]},
			Severity:            "INFO",
			CreatedAt:           createdAt,
			Version:             aws.String("abc"),
		},
	}

	result := getAlertsToRetry(failedStatuses, 10)

	assert.Equal(t, expectedResult, result)
}
