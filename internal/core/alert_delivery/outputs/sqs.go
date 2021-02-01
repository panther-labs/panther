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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
)

// Tests can replace this with a mock implementation
var getSqsClient = buildSqsClient

// Sqs sends an alert to an SQS Queue.
// nolint: dupl
func (client *OutputClient) Sqs(ctx context.Context, alert *deliverymodel.Alert, config *outputModels.SqsConfig) *AlertDeliveryResponse {
	notification := generateNotificationFromAlert(alert)

	serializedMessage, err := jsoniter.MarshalToString(notification)
	if err != nil {
		zap.L().Error("Failed to serialize message", zap.Error(err))
		return &AlertDeliveryResponse{
			StatusCode: 500,
			Message:    "Failed to serialize message",
			Permanent:  true,
			Success:    false,
		}
	}

	sqsSendMessageInput := &sqs.SendMessageInput{
		QueueUrl:    aws.String(config.QueueURL),
		MessageBody: aws.String(serializedMessage),
	}

	sqsClient := getSqsClient(client.session, config.QueueURL)

	response, err := sqsClient.SendMessageWithContext(ctx, sqsSendMessageInput)
	if err != nil {
		zap.L().Error("Failed to send message to SQS queue", zap.Error(err))
		return getAlertResponseFromSQSError(err)
	}

	if response == nil {
		return &AlertDeliveryResponse{
			StatusCode: 500,
			Message:    "sqs response was nil",
			Permanent:  false,
			Success:    false,
		}
	}

	if response.MessageId == nil {
		return &AlertDeliveryResponse{
			StatusCode: 500,
			Message:    "sqs messageId was nil",
			Permanent:  false,
			Success:    false,
		}
	}

	return &AlertDeliveryResponse{
		StatusCode: 200,
		Message:    aws.StringValue(response.MessageId),
		Permanent:  false,
		Success:    true,
	}
}

func buildSqsClient(awsSession *session.Session, queueURL string) sqsiface.SQSAPI {
	// Queue URL is like "https://sqs.us-west-2.amazonaws.com/123456789012/panther-alert-queue"
	parts := strings.Split(queueURL, ".")
	if len(parts) == 1 {
		panic("expected queueURL with periods, found none: " + queueURL)
	}
	region := strings.Split(queueURL, ".")[1]
	return sqs.New(awsSession, aws.NewConfig().WithRegion(region))
}
