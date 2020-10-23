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
		AnalysisID:          "policyId",
		AnalysisDescription: aws.String("policyDescription"),
		Severity:            "severity",
		Runbook:             aws.String("runbook"),
		CreatedAt:           createdAtTime,
		Context: map[string]interface{}{
			"key": "value",
		},
	}

	analysisName := "policyName"
	for i := 0; i < 100; i++ {
		analysisName += "a"
	}
	alert.AnalysisName = aws.String(analysisName)

	defaultMessage := Notification{
		ID:          "policyId",
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

	defaultSerializedMessage, err := jsoniter.MarshalToString(defaultMessage)
	require.NoError(t, err)

	expectedSnsMessage := &snsMessage{
		DefaultMessage: defaultSerializedMessage,
		EmailMessage: analysisName + " failed on new resources\nFor more details please visit: https://panther.io/policies/policyId\n" +
			"Severity: severity\nRunbook: runbook\nDescription: policyDescription",
	}
	expectedSerializedSnsMessage, _ := jsoniter.MarshalToString(expectedSnsMessage)
	expectedSnsPublishInput := &sns.PublishInput{
		TopicArn:         &snsOutputConfig.TopicArn,
		Message:          &expectedSerializedSnsMessage,
		MessageStructure: aws.String("json"),
		Subject:          aws.String("Policy Failure: " + analysisName[0:84]),
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
