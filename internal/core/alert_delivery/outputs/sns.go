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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

type snsMessage struct {
	DefaultMessage string `json:"default"`
	// EmailMessage contains the message that will be delivered to email subscribers
	EmailMessage string `json:"email"`
}

// Sns sends an alert to an SNS Topic.
// nolint: dupl
func (client *OutputClient) Sns(alert *alertmodels.Alert, config *outputmodels.SnsConfig) *AlertDeliveryError {
	notification := generateNotificationFromAlert(alert)
	serializedDefaultMessage, err := jsoniter.MarshalToString(notification)
	if err != nil {
		errorMsg := "Failed to serialize default message"
		zap.L().Error(errorMsg, zap.Error(errors.WithStack(err)))
		return &AlertDeliveryError{Message: errorMsg, Permanent: true}
	}

	outputMessage := &snsMessage{
		DefaultMessage: serializedDefaultMessage,
		EmailMessage:   generateDetailedAlertMessage(alert),
	}

	serializedMessage, err := jsoniter.MarshalToString(outputMessage)
	if err != nil {
		errorMsg := "Failed to serialize message"
		zap.L().Error(errorMsg, zap.Error(errors.WithStack(err)))
		return &AlertDeliveryError{Message: errorMsg, Permanent: true}
	}

	snsMessageInput := &sns.PublishInput{
		TopicArn: aws.String(config.TopicArn),
		Message:  aws.String(serializedMessage),
		// Subject is optional in case the topic is subscribed to Email
		Subject:          aws.String(generateAlertTitle(alert)),
		MessageStructure: aws.String("json"),
	}

	snsClient, err := client.getSnsClient(config.TopicArn)
	if err != nil {
		errorMsg := "Failed to create SNS client for topic"
		zap.L().Error(errorMsg, zap.Error(errors.WithStack(err)))
		return &AlertDeliveryError{Message: errorMsg, Permanent: true}
	}

	_, err = snsClient.Publish(snsMessageInput)
	if err != nil {
		errorMsg := "Failed to send message to SNS topic"
		zap.L().Error(errorMsg, zap.Error(errors.WithStack(err)))
		return &AlertDeliveryError{Message: errorMsg}
	}
	return nil
}

func (client *OutputClient) getSnsClient(topicArn string) (snsiface.SNSAPI, error) {
	parsedArn, err := arn.Parse(topicArn)
	if err != nil {
		zap.L().Error("failed to parse topic ARN", zap.Error(err))
		return nil, err
	}
	snsClient, ok := client.snsClients[parsedArn.Region]
	if !ok {
		snsClient = sns.New(client.session, aws.NewConfig().WithRegion(parsedArn.Region))
		client.snsClients[parsedArn.Region] = snsClient
	}
	return snsClient, nil
}
