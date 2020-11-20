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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
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
	// Newline in analysis name is used for SNS subject restriction input validation
	analysisName := "\npolicyName"
	for i := 0; i < 100; i++ {
		analysisName += "a"
	}
	alert.AnalysisName = aws.String(analysisName)

	expectedDefaultMessage := Notification{
		ID:          "policyId",
		Type:        alertModels.PolicyType,
		Name:        aws.String(analysisName),
		Description: aws.String("policyDescription"),
		Severity:    "severity",
		Runbook:     aws.String("runbook"),
		CreatedAt:   createdAtTime,
		Link:        "https://panther.io/policies/policyId",
		Title:       "Policy Failure: " + analysisName,
		Tags:        []string{},
		AlertContext: map[string]interface{}{
			"key": "value",
		},
	}
	expectedDefaultSerializedMessage, err := jsoniter.MarshalToString(expectedDefaultMessage)
	require.NoError(t, err)

	expectedSnsMessage := &snsMessage{
		DefaultMessage: expectedDefaultSerializedMessage,
		EmailMessage: analysisName + " failed on new resources\nFor more details please visit: https://panther.io/policies/policyId\n" +
			"Severity: severity\nRunbook: runbook\nDescription: policyDescription\nAlertContext: {\"key\":\"value\"}",
	}
	expectedSerializedSnsMessage, err := jsoniter.MarshalToString(expectedSnsMessage)
	require.NoError(t, err)
	
	// Corrected input after validation
	expectedSnsPublishInput := &sns.PublishInput{
		TopicArn:         &snsOutputConfig.TopicArn,
		Message:          &expectedSerializedSnsMessage,
		MessageStructure: aws.String("json"),
		Subject:          aws.String("Policy Failure: " + analysisName[1:85]),
	}

	client.On("Publish", expectedSnsPublishInput).Return(&sns.PublishOutput{MessageId: aws.String("messageId")}, nil)
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
