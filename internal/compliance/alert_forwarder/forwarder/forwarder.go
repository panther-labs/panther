package forwarder

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
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

var (
	alertQueueURL                 = os.Getenv("ALERTING_QUEUE_URL")
	awsSession                    = session.Must(session.NewSession())
	sqsClient     sqsiface.SQSAPI = sqs.New(awsSession)
)

// Handle forwards an alert to the alert delivery SQS queue
func Handle(event *models.Alert) error {
	zap.L().Info("received alert", zap.String("policyId", event.AnalysisID))

	msgBody, err := jsoniter.Marshal(event)
	if err != nil {
		return err
	}
	input := &sqs.SendMessageInput{
		QueueUrl:    aws.String(alertQueueURL),
		MessageBody: aws.String(string(msgBody)),
	}
	_, err = sqsClient.SendMessage(input)
	if err != nil {
		zap.L().Warn("failed to send message to remediation", zap.Error(err))
		return err
	}
	zap.L().Info("successfully triggered alert action")

	return nil
}
