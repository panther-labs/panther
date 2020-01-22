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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	outputmodels "github.com/panther-labs/panther/api/lambda/outputs/models"
	alertmodels "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

// Sns sends an alert to an SNS Topic.
// nolint: dupl
func (client *OutputClient) Sns(alert *alertmodels.Alert, config *outputmodels.SnsConfig) *AlertDeliveryError {
	outputMessage := &snsMessage{
		DefaultMessage: snsDefaultMessage{
			ID:          alert.PolicyID,
			Name:        alert.PolicyName,
			VersionID:   alert.PolicyVersionID,
			Description: alert.PolicyDescription,
			Runbook:     alert.Runbook,
			Severity:    alert.Severity,
			Tags:        alert.Tags,
		},
		EmailMessage: generateEmailContent(alert),
	}

	serializedMessage, err := jsoniter.MarshalToString(outputMessage)
	if err != nil {
		zap.L().Error("Failed to serialize message", zap.Error(err))
		return &AlertDeliveryError{Message: "Failed to serialize message"}
	}

	snsMessageInput := &sns.PublishInput{
		TopicArn: config.TopicArn,
		Message:  aws.String(serializedMessage),
		// Subject is optional in case the topic is subscribed to Email
		Subject:          generateAlertTitle(alert),
		MessageStructure: aws.String("json"),
	}

	snsClient, err := client.getSnsClient(*config.TopicArn)
	if err != nil {
		return &AlertDeliveryError{Message: "Failed to create SNS client for topic", Permanent: true}
	}

	_, err = snsClient.Publish(snsMessageInput)
	if err != nil {
		zap.L().Error("Failed to send message to SNS topic", zap.Error(err))
		return &AlertDeliveryError{Message: "Failed to send message to SNS topic"}
	}
	return nil
}

type snsMessage struct {
	DefaultMessage snsDefaultMessage `json:"default"`
	// EmailMessage contains the message that will be delivered to email subscribers
	EmailMessage string `json:"email"`
}

//snsOutputMessage contains the fields that will be included in the  default SNS message
type snsDefaultMessage struct {
	ID          *string   `json:"id"`
	Name        *string   `json:"name,omitempty"`
	VersionID   *string   `json:"versionId,omitempty"`
	Description *string   `json:"description,omitempty"`
	Runbook     *string   `json:"runbook,omitempty"`
	Severity    *string   `json:"severity"`
	Tags        []*string `json:"tags,omitempty"`
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
