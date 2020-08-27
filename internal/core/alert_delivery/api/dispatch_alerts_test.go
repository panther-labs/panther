package api

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	jsoniter "github.com/json-iterator/go"
	deliveryModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestGetAlerts(t *testing.T) {
	alertID := aws.String("alert-id")
	outputIds := []string{"output-id-1", "output-id-2", "output-id-3"}

	alert := &deliveryModels.Alert{
		AlertID:             alertID,
		AnalysisDescription: aws.String("A test alert"),
		AnalysisID:          "Test.Analysis.ID",
		AnalysisName:        aws.String("Test Analysis Name"),
		Runbook:             aws.String("A runbook link"),
		Title:               aws.String("Test Alert"),
		RetryCount:          0,
		Tags:                []string{"test", "alert"},
		Type:                deliveryModels.RuleType,
		OutputIds:           outputIds,
		Severity:            "INFO",
		CreatedAt:           time.Now().UTC(),
		Version:             aws.String("abc"),
	}
	bodyBytes, err := jsoniter.Marshal(alert)
	require.NoError(t, err)
	bodyString := string(bodyBytes)
	input := []*deliveryModels.DispatchAlertsInput{
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
	expectedResult := []*deliveryModels.Alert{alert}
	result := getAlerts(input)

	assert.Equal(t, expectedResult, result)
}

// func TestGetAlertOutputMap(t *testing.T) {

// }

// func TestGetAlertOutputMapError(t *testing.T) {

// }
