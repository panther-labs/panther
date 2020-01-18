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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/aws/aws-sdk-go/service/ses/sesiface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

type mockSesClient struct {
	sesiface.SESAPI
	mock.Mock
}

var alert = &alertmodels.Alert{
	PolicyName:        aws.String("policyName"),
	PolicyID:          aws.String("policyId"),
	PolicyDescription: aws.String("policyDescription"),
	Severity:          aws.String("severity"),
	Runbook:           aws.String("runbook"),
}
var outputConfig = &outputmodels.EmailConfig{
	DestinationAddress: aws.String("destinationAddress"),
}

func (m *mockSesClient) SendEmail(input *ses.SendEmailInput) (*ses.SendEmailOutput, error) {
	args := m.Called(input)
	return args.Get(0).(*ses.SendEmailOutput), args.Error(1)
}

func init() {
	policyURLPrefix = "https://panther.io/policies/"
	alertURLPrefix = "https://panther.io/alerts/"
	sesConfigurationSet = "sesConfigurationSet"
}

func TestSendEmail(t *testing.T) {
	client := &mockSesClient{}
	outputClient := &OutputClient{sesClient: client, mailFrom: aws.String("email@email.com")}

	expectedEmailInput := &ses.SendEmailInput{
		ConfigurationSetName: aws.String("sesConfigurationSet"),
		Source:               aws.String("email@email.com"),
		Destination:          &ses.Destination{ToAddresses: []*string{aws.String("destinationAddress")}},
		Message: &ses.Message{
			Subject: &ses.Content{
				Charset: aws.String("UTF-8"),
				Data:    aws.String("Policy Failure: policyName"),
			},
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: aws.String("UTF-8"),
					Data: aws.String("<h2>Message</h2><a href='https://panther.io/policies/policyId'>" +
						"policyName failed on new resources</a><br><h2>Severity</h2>severity<br>" +
						"<h2>Runbook</h2>runbook<br><h2>Description</h2>policyDescription"),
				},
			},
		},
	}

	client.On("SendEmail", expectedEmailInput).Return(&ses.SendEmailOutput{}, nil)
	result := outputClient.Email(alert, outputConfig)
	assert.Nil(t, result)
	client.AssertExpectations(t)
}

func TestSendEmailRule(t *testing.T) {
	client := &mockSesClient{}
	outputClient := &OutputClient{sesClient: client, mailFrom: aws.String("email@email.com")}

	var alert = &alertmodels.Alert{
		PolicyName:        aws.String("ruleName"),
		PolicyID:          aws.String("ruleId"),
		PolicyDescription: aws.String("ruleDescription"),
		Severity:          aws.String("severity"),
		Runbook:           aws.String("runbook"),
		Type:              aws.String(alertmodels.RuleType),
		AlertID:           aws.String("alertId"),
	}

	expectedEmailInput := &ses.SendEmailInput{
		ConfigurationSetName: aws.String("sesConfigurationSet"),
		Source:               aws.String("email@email.com"),
		Destination:          &ses.Destination{ToAddresses: []*string{aws.String("destinationAddress")}},
		Message: &ses.Message{
			Subject: &ses.Content{
				Charset: aws.String("UTF-8"),
				Data:    aws.String("New Alert: ruleName"),
			},
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: aws.String("UTF-8"),
					Data: aws.String("<h2>Message</h2><a href='https://panther.io/alerts/alertId'>" +
						"ruleName failed</a><br><h2>Severity</h2>severity<br>" +
						"<h2>Runbook</h2>runbook<br><h2>Description</h2>ruleDescription"),
				},
			},
		},
	}

	client.On("SendEmail", expectedEmailInput).Return(&ses.SendEmailOutput{}, nil)
	result := outputClient.Email(alert, outputConfig)
	assert.Nil(t, result)
	client.AssertExpectations(t)
}

func TestSendEmailPermanentError(t *testing.T) {
	client := &mockSesClient{}
	outputClient := &OutputClient{sesClient: client}

	client.On("SendEmail", mock.Anything).Return(
		&ses.SendEmailOutput{},
		errors.New("message failed"),
	)

	result := outputClient.Email(alert, outputConfig)
	require.Error(t, result)
	assert.Equal(t, &AlertDeliveryError{Message: "request failed message failed", Permanent: true}, result)
	client.AssertExpectations(t)
}

func TestSendEmailTemporaryError(t *testing.T) {
	client := &mockSesClient{}
	outputClient := &OutputClient{sesClient: client}

	client.On("SendEmail", mock.Anything).Return(
		&ses.SendEmailOutput{},
		awserr.New(ses.ErrCodeMessageRejected, "Message rejected", nil),
	)

	result := outputClient.Email(alert, outputConfig)
	require.Error(t, result)
	assert.Equal(t, &AlertDeliveryError{Message: "request failed MessageRejected: Message rejected", Permanent: false}, result)
	client.AssertExpectations(t)
}
