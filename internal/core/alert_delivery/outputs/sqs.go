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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

// Sqs sends an alert to an SQS Queue.
// nolint: dupl
func (client *OutputClient) Sqs(alert *alertmodels.Alert, config *outputmodels.SqsConfig) *AlertDeliveryError {
	outputMessage := &sqsOutputMessage{
		ID:          alert.PolicyID,
		Name:        alert.PolicyName,
		VersionID:   alert.PolicyVersionID,
		Description: alert.PolicyDescription,
		Runbook:     alert.Runbook,
		Severity:    alert.Severity,
		Tags:        alert.Tags,
	}

	serializedMessage, err := jsoniter.MarshalToString(outputMessage)
	if err != nil {
		zap.L().Error("Failed to serialize message", zap.Error(err))
		return &AlertDeliveryError{Message: "Failed to serialize message"}
	}

	sqsSendMessageInput := &sqs.SendMessageInput{
		QueueUrl:    config.QueueURL,
		MessageBody: aws.String(serializedMessage),
	}

	sqsClient := client.getSqsClient(*config.QueueURL)

	_, err = sqsClient.SendMessage(sqsSendMessageInput)
	if err != nil {
		zap.L().Error("Failed to send message to SQS queue", zap.Error(err))
		return &AlertDeliveryError{Message: "Failed to send message to SQS queue"}
	}
	return nil
}

//sqsOutputMessage contains the fields that will be included in the SQS message
type sqsOutputMessage struct {
	ID          *string   `json:"id"`
	Name        *string   `json:"name,omitempty"`
	VersionID   *string   `json:"versionId,omitempty"`
	Description *string   `json:"description,omitempty"`
	Runbook     *string   `json:"runbook,omitempty"`
	Severity    *string   `json:"severity"`
	Tags        []*string `json:"tags,omitempty"`
}

func (client *OutputClient) getSqsClient(queueURL string) sqsiface.SQSAPI {
	// Queue URL is like "https://sqs.us-west-2.amazonaws.com/123456789012/panther-alert-queue"
	region := strings.Split(queueURL, ".")[1]
	sqsClient, ok := client.sqsClients[region]
	if !ok {
		sqsClient = sqs.New(client.session, aws.NewConfig().WithRegion(region))
		client.sqsClients[region] = sqsClient
	}
	return sqsClient
}
