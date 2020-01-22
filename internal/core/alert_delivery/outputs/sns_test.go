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
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

type mockSnsClient struct {
	snsiface.SNSAPI
	mock.Mock
}

func (m *mockSnsClient) Publish(input *sns.PublishInput) (*sns.PublishOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*sns.PublishOutput), args.Error(1)
}

func TestSendSns(t *testing.T) {
	client := &mockSnsClient{}
	outputClient := &OutputClient{snsClients: map[string]snsiface.SNSAPI{"us-west-2": client}}

	snsOutputConfig := &outputmodels.SnsConfig{
		TopicArn: aws.String("arn:aws:sns:us-west-2:123456789012:test-sns-output"),
	}
	alert := &alertmodels.Alert{
		PolicyName:        aws.String("policyName"),
		PolicyID:          aws.String("policyId"),
		PolicyDescription: aws.String("policyDescription"),
		Severity:          aws.String("severity"),
		Runbook:           aws.String("runbook"),
	}

	expectedSnsMessage := &snsMessage{
		DefaultMessage: `{"id":"policyId","name":"policyName","description":"policyDescription","runbook":"runbook","severity":"severity"}`,
		EmailMessage:   "policyName failed on new resources\nFor more details please visit: https://panther.io/policies/policyId\n" +
			"Severity: severity\nRunbook: runbook\nDescription:policyDescription",
	}
	expectedSerializedSnsMessage, _ := jsoniter.MarshalToString(expectedSnsMessage)
	expectedSnsPublishInput := &sns.PublishInput{
		TopicArn:         snsOutputConfig.TopicArn,
		Message:          aws.String(expectedSerializedSnsMessage),
		MessageStructure: aws.String("json"),
		Subject:          aws.String("Policy Failure: policyName"),
	}

	client.On("Publish", expectedSnsPublishInput).Return(&sns.PublishOutput{}, nil)
	result := outputClient.Sns(alert, snsOutputConfig)
	assert.Nil(t, result)
	client.AssertExpectations(t)
}
