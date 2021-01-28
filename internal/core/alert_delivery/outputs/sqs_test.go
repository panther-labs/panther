package outputs

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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestSendSqs(t *testing.T) {
	client := &testutils.SqsMock{}
	outputClient := &OutputClient{}

	sqsOutputConfig := &outputModels.SqsConfig{
		QueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/test-output",
	}
	alert := &deliverymodel.Alert{
		AlertID:             aws.String("alertId"),
		AnalysisName:        aws.String("policyName"),
		Type:                deliverymodel.PolicyType,
		AnalysisID:          "policyId",
		AnalysisDescription: "policyDescription",
		Severity:            "severity",
		Runbook:             "runbook",
		Context: map[string]interface{}{
			"key": "value",
		},
	}

	expectedSqsMessage := &Notification{
		ID:          alert.AnalysisID,
		AlertID:     aws.String("alertId"),
		Type:        deliverymodel.PolicyType,
		Name:        alert.AnalysisName,
		Description: aws.String(alert.AnalysisDescription),
		Severity:    alert.Severity,
		Runbook:     aws.String(alert.Runbook),
		Link:        "https://panther.io/alerts/alertId",
		Title:       "Policy Failure: policyName",
		Tags:        []string{},
		AlertContext: map[string]interface{}{
			"key": "value",
		},
	}
	expectedSerializedSqsMessage, err := jsoniter.MarshalToString(expectedSqsMessage)
	require.NoError(t, err)
	expectedSqsSendMessageInput := &sqs.SendMessageInput{
		QueueUrl:    &sqsOutputConfig.QueueURL,
		MessageBody: &expectedSerializedSqsMessage,
	}
	ctx := context.Background()
	client.On("SendMessageWithContext",
		ctx,
		expectedSqsSendMessageInput,
	).Return(&sqs.SendMessageOutput{MessageId: aws.String("messageId")}, nil)
	getSqsClient = func(*session.Session, string) sqsiface.SQSAPI {
		return client
	}

	result := outputClient.Sqs(ctx, alert, sqsOutputConfig)
	assert.NotNil(t, result)
	assert.Equal(t, &AlertDeliveryResponse{
		Message:    "messageId",
		StatusCode: 200,
		Success:    true,
		Permanent:  false,
	}, result)
	client.AssertExpectations(t)
}
