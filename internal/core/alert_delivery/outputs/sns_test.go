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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	alertModels "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestSendSns(t *testing.T) {
	client := &testutils.SnsMock{}
	outputClient := &OutputClient{}

	snsOutputConfig := &outputModels.SnsConfig{
		TopicArn: "arn:aws:sns:us-west-2:123456789012:test-sns-output",
	}

	createdAtTime := time.Now()
	alert := &alertModels.Alert{
		AnalysisName:        aws.String("policyName"),
		Type:                alertModels.PolicyType,
		AnalysisID:          "policyId",
		AnalysisDescription: aws.String("policyDescription"),
		Severity:            "severity",
		Runbook:             aws.String("runbook"),
		CreatedAt:           createdAtTime,
		Context: map[string]interface{}{
			"key": "value",
		},
	}

	defaultMessage := Notification{
		ID:          "policyId",
		Type:        alertModels.PolicyType,
		Name:        aws.String("policyName"),
		Description: aws.String("policyDescription"),
		Severity:    "severity",
		Runbook:     aws.String("runbook"),
		CreatedAt:   createdAtTime,
		Link:        "https://panther.io/policies/policyId",
		Title:       "Policy Failure: policyName",
		Tags:        []string{},
		AlertContext: map[string]interface{}{
			"key": "value",
		},
	}

	defaultSerializedMessage, err := jsoniter.MarshalToString(defaultMessage)
	require.NoError(t, err)

	expectedSnsMessage := &snsMessage{
		DefaultMessage: defaultSerializedMessage,
		EmailMessage: "policyName failed on new resources\nFor more details please visit: https://panther.io/policies/policyId\n" +
			"Severity: severity\nRunbook: runbook\nDescription: policyDescription\nAlertContext: {\"key\":\"value\"}",
	}
	expectedSerializedSnsMessage, err := jsoniter.MarshalToString(expectedSnsMessage)
	require.NoError(t, err)
	expectedSnsPublishInput := &sns.PublishInput{
		TopicArn:         &snsOutputConfig.TopicArn,
		Message:          &expectedSerializedSnsMessage,
		MessageStructure: aws.String("json"),
		Subject:          aws.String("Policy Failure: policyName"),
	}

	client.On("Publish", expectedSnsPublishInput).Return(&sns.PublishOutput{MessageId: aws.String("messageId")}, nil).Once()
	getSnsClient = func(*session.Session, string) (snsiface.SNSAPI, error) {
		return client, nil
	}

	result := outputClient.Sns(alert, snsOutputConfig)
	assert.NotNil(t, result)
	assert.Equal(t, &AlertDeliveryResponse{
		Message:    "messageId",
		StatusCode: 200,
		Success:    true,
		Permanent:  false,
	}, result)
	client.AssertExpectations(t)
}

func TestTruncateSnsTitle(t *testing.T) {
	client := &testutils.SnsMock{}
	outputClient := &OutputClient{}

	snsOutputConfig := &outputModels.SnsConfig{
		TopicArn: "arn:aws:sns:us-west-2:123456789012:test-sns-output",
	}

	var title string
	// Generate a title that has
	// 100 times the new line character (it should be removed)
	// 100 times the character 'a'
	for i := 0; i < 100; i++ {
		title += "\na"
	}
	// The email subject we send should be the title but:
	// 1. It should have no new lines
	// 2. It should have 100 characters maximum
	// 3. It should finish with 3 dots '...' at the end
	expectedEmailSubject := "New Alert: "
	for i := 0; i < 86; i++ {
		expectedEmailSubject += "a"
	}
	expectedEmailSubject += "..."

	createdAtTime := time.Now()
	alert := &alertModels.Alert{
		AlertID:             aws.String("alertID"),
		AnalysisName:        aws.String("ruleName"),
		Type:                alertModels.RuleType,
		AnalysisID:          "ruleId",
		AnalysisDescription: aws.String("ruleDescription"),
		Severity:            "severity",
		Runbook:             aws.String("runbook"),
		CreatedAt:           createdAtTime,
		Title:               &title,
		Tags:                []string{},
		Context: map[string]interface{}{
			"key": "value",
		},
	}

	defaultMessage := Notification{
		ID:          alert.AnalysisID,
		AlertID:     alert.AlertID,
		Type:        alert.Type,
		Name:        alert.AnalysisName,
		Description: alert.AnalysisDescription,
		Severity:    alert.Severity,
		Runbook:     alert.Runbook,
		CreatedAt:   alert.CreatedAt,
		Title:       "New Alert: " + title,
		Link:        "https://panther.io/alerts/alertID",
		Tags:        []string{},
		AlertContext: map[string]interface{}{
			"key": "value",
		},
	}

	defaultSerializedMessage, err := jsoniter.MarshalToString(defaultMessage)
	require.NoError(t, err)

	expectedSnsMessage := &snsMessage{
		DefaultMessage: defaultSerializedMessage,
		EmailMessage: "ruleName triggered\nFor more details please visit: https://panther.io/alerts/alertID\nSeverity: severity\n" +
			"Runbook: runbook\nDescription: ruleDescription\nAlertContext: {\"key\":\"value\"}",
	}
	expectedSerializedSnsMessage, err := jsoniter.MarshalToString(expectedSnsMessage)
	require.NoError(t, err)

	expectedSnsPublishInput := &sns.PublishInput{
		TopicArn:         &snsOutputConfig.TopicArn,
		Message:          &expectedSerializedSnsMessage,
		MessageStructure: aws.String("json"),
		Subject:          aws.String(expectedEmailSubject),
	}

	client.On("Publish", expectedSnsPublishInput).Return(&sns.PublishOutput{MessageId: aws.String("messageId")}, nil).Once()
	getSnsClient = func(*session.Session, string) (snsiface.SNSAPI, error) {
		return client, nil
	}
	result := outputClient.Sns(alert, snsOutputConfig)
	assert.NotNil(t, result)
	assert.Equal(t, &AlertDeliveryResponse{
		Message:    "messageId",
		StatusCode: 200,
		Success:    true,
		Permanent:  false,
	}, result)
	client.AssertExpectations(t)
}

func TestResendEmailSubject(t *testing.T) {
	client := &testutils.SnsMock{}
	outputClient := &OutputClient{}
	getSnsClient = func(*session.Session, string) (snsiface.SNSAPI, error) {
		return client, nil
	}

	snsOutputConfig := &outputModels.SnsConfig{
		TopicArn: "arn:aws:sns:us-west-2:123456789012:test-sns-output",
	}

	createdAtTime := time.Now()
	alert := &alertModels.Alert{
		AlertID:             aws.String("alertID"),
		AnalysisName:        aws.String("ruleName"),
		Type:                alertModels.RuleType,
		AnalysisID:          "ruleId",
		AnalysisDescription: aws.String("ruleDescription"),
		Severity:            "severity",
		Runbook:             aws.String("runbook"),
		CreatedAt:           createdAtTime,
		Title:               aws.String("title"),
		Tags:                []string{},
		Context: map[string]interface{}{
			"key": "value",
		},
	}

	defaultMessage := Notification{
		ID:          alert.AnalysisID,
		AlertID:     alert.AlertID,
		Type:        alert.Type,
		Name:        alert.AnalysisName,
		Description: alert.AnalysisDescription,
		Severity:    alert.Severity,
		Runbook:     alert.Runbook,
		CreatedAt:   alert.CreatedAt,
		Title:       "New Alert: " + *alert.Title,
		Link:        "https://panther.io/alerts/alertID",
		Tags:        []string{},
		AlertContext: map[string]interface{}{
			"key": "value",
		},
	}

	defaultSerializedMessage, err := jsoniter.MarshalToString(defaultMessage)
	require.NoError(t, err)

	expectedSnsMessage := &snsMessage{
		DefaultMessage: defaultSerializedMessage,
		EmailMessage: "ruleName triggered\nFor more details please visit: https://panther.io/alerts/alertID\nSeverity: severity\n" +
			"Runbook: runbook\nDescription: ruleDescription\nAlertContext: {\"key\":\"value\"}",
	}
	expectedSerializedSnsMessage, err := jsoniter.MarshalToString(expectedSnsMessage)
	require.NoError(t, err)

	expectedSnsPublishInput := &sns.PublishInput{
		TopicArn:         &snsOutputConfig.TopicArn,
		Message:          &expectedSerializedSnsMessage,
		MessageStructure: aws.String("json"),
		// This is the default email title we are going to use
		// after the SNS client has returned an 'InvalidParameter' error
		Subject: aws.String("New Panther Alert"),
	}

	// First invocation returns "InvalidParameterError"
	client.On("Publish", mock.Anything).Return(&sns.PublishOutput{}, awserr.New(sns.ErrCodeInvalidParameterException, "", nil)).Once()
	// We retry second time, this time with the default title
	client.On("Publish", expectedSnsPublishInput).Return(&sns.PublishOutput{MessageId: aws.String("messageId")}, nil)

	result := outputClient.Sns(alert, snsOutputConfig)
	assert.NotNil(t, result)
	assert.Equal(t, &AlertDeliveryResponse{
		Message:    "messageId",
		StatusCode: 200,
		Success:    true,
		Permanent:  false,
	}, result)
	client.AssertExpectations(t)
}
