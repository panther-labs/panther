package outputs

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"github.com/stretchr/testify/mock"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

type mockSqsClient struct {
	sqsiface.SQSAPI
	mock.Mock
}

func (m *mockSqsClient) SendMessage(input *sqs.SendMessageInput) (*sqs.SendMessageOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sqs.SendMessageOutput), args.Error(1)
}

func TestSendSqs(t *testing.T) {
	client := &mockSqsClient{}
	outputClient := &OutputClient{sqsClients: map[string]sqsiface.SQSAPI{"us-west-2": client}}

	sqsOutputConfig := &outputmodels.SqsConfig{
		QueueURL: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/test-output"),
	}
	alert := &alertmodels.Alert{
		PolicyName:        aws.String("policyName"),
		PolicyID:          aws.String("policyId"),
		PolicyDescription: aws.String("policyDescription"),
		Severity:          aws.String("severity"),
		Runbook:           aws.String("runbook"),
	}

	expectedSqsMessage := &sqsOutputMessage{
		ID:          alert.PolicyID,
		Name:        alert.PolicyName,
		Description: alert.PolicyDescription,
		Severity:    alert.Severity,
		Runbook:     alert.Runbook,
	}
	expectedSerializedSqsMessage, _ := jsoniter.MarshalToString(expectedSqsMessage)
	expectedSqsSendMessageInput := &sqs.SendMessageInput{
		QueueUrl:    sqsOutputConfig.QueueURL,
		MessageBody: aws.String(expectedSerializedSqsMessage),
	}

	client.On("SendMessage", expectedSqsSendMessageInput).Return(&sqs.SendMessageOutput{}, nil)
	result := outputClient.Sqs(alert, sqsOutputConfig)
	assert.Nil(t, result)
	client.AssertExpectations(t)
}
