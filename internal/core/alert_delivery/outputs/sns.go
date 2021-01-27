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
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	outputModels "github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/awsutils"
)

type snsMessage struct {
	DefaultMessage string `json:"default"`
	// EmailMessage contains the message that will be delivered to email subscribers
	EmailMessage string `json:"email"`
}

// Tests can replace this with a mock implementation
var getSnsClient = buildSnsClient

// SNS subject size limit
const maxTitleSize = 100

// Sns sends an alert to an SNS Topic.
// nolint: dupl
func (client *OutputClient) Sns(ctx context.Context, alert *deliverymodel.Alert, config *outputModels.SnsConfig) *AlertDeliveryResponse {
	notification := generateNotificationFromAlert(alert)
	serializedDefaultMessage, err := jsoniter.MarshalToString(notification)
	if err != nil {
		errorMsg := "Failed to serialize default message"
		zap.L().Error(errorMsg, zap.Error(errors.WithStack(err)))
		return &AlertDeliveryResponse{
			StatusCode: 500,
			Message:    errorMsg,
			Permanent:  true,
			Success:    false,
		}
	}

	outputMessage := &snsMessage{
		DefaultMessage: serializedDefaultMessage,
		EmailMessage:   generateDetailedAlertMessage(alert),
	}

	serializedMessage, err := jsoniter.MarshalToString(outputMessage)
	if err != nil {
		errorMsg := "Failed to serialize message"
		zap.L().Error(errorMsg, zap.Error(errors.WithStack(err)))
		return &AlertDeliveryResponse{
			StatusCode: 500,
			Message:    errorMsg,
			Permanent:  true,
			Success:    false,
		}
	}
	// Remove newlines in title
	title := strings.ReplaceAll(generateAlertTitle(alert), "\n", "")
	// Trim title to the AWS SNS 100 char limit
	if len(title) > maxTitleSize {
		title = title[:maxTitleSize-3] + "..."
	}

	snsMessageInput := &sns.PublishInput{
		TopicArn: aws.String(config.TopicArn),
		Message:  aws.String(serializedMessage),
		// Subject is optional in case the topic is subscribed to Email
		Subject:          aws.String(title),
		MessageStructure: aws.String("json"),
	}

	snsClient, err := getSnsClient(client.session, config.TopicArn)
	if err != nil {
		errorMsg := "Failed to create SNS client for topic"
		zap.L().Error(errorMsg, zap.Error(errors.WithStack(err)))
		return &AlertDeliveryResponse{
			StatusCode: 500,
			Message:    errorMsg,
			Permanent:  true,
			Success:    false,
		}
	}

	response, err := snsClient.PublishWithContext(ctx, snsMessageInput)
	if err != nil {
		// Catch title edge cases and make SNS API call with generic title
		if awsutils.IsAnyError(err, sns.ErrCodeInvalidParameterException) {
			const defaultTitle = "New Panther Alert"
			snsMessageInput.Subject = aws.String(defaultTitle)
			response, err = snsClient.PublishWithContext(ctx, snsMessageInput)
			if err != nil {
				zap.L().Error("Failed to send message to SNS topic", zap.Error(err))
				return getAlertResponseFromSNSError(err)
			}
		}
	}

	if response == nil {
		return &AlertDeliveryResponse{
			StatusCode: 500,
			Message:    "sns response was nil",
			Permanent:  false,
			Success:    false,
		}
	}

	if response.MessageId == nil {
		return &AlertDeliveryResponse{
			StatusCode: 500,
			Message:    "sns messageId was nil",
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

func buildSnsClient(awsSession *session.Session, topicArn string) (snsiface.SNSAPI, error) {
	parsedArn, err := arn.Parse(topicArn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse SNS topic ARN")
	}
	return sns.New(awsSession, aws.NewConfig().WithRegion(parsedArn.Region)), nil
}
