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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestSendSqs(t *testing.T) {
	client := &testutils.SqsMock{}
	outputClient := &OutputClient{sqsClients: map[string]sqsiface.SQSAPI{"us-west-2": client}}

	sqsOutputConfig := &outputmodels.SqsConfig{
		QueueURL: "https://sqs.us-west-2.amazonaws.com/123456789012/test-output",
	}
	alert := &alertmodels.Alert{
		AnalysisName:        aws.String("policyName"),
		AnalysisID:          "policyId",
		AnalysisDescription: aws.String("policyDescription"),
		Severity:            "severity",
		Runbook:             aws.String("runbook"),
	}

	expectedSqsMessage := &Notification{
		AnalysisID:   alert.AnalysisID,
		AnalysisName: alert.AnalysisName,
		Description:  alert.AnalysisDescription,
		Severity:     alert.Severity,
		Runbook:      alert.Runbook,
		Link:         "https://panther.io/policies/policyId",
		Title:        "Policy Failure: policyName",
		Tags:         []string{},
	}
	expectedSerializedSqsMessage, err := jsoniter.MarshalToString(expectedSqsMessage)
	require.NoError(t, err)
	expectedSqsSendMessageInput := &sqs.SendMessageInput{
		QueueUrl:    &sqsOutputConfig.QueueURL,
		MessageBody: &expectedSerializedSqsMessage,
	}

	client.On("SendMessage", expectedSqsSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)
	result := outputClient.Sqs(alert, sqsOutputConfig)
	assert.Nil(t, result)
	client.AssertExpectations(t)
}
