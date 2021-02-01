package requeue

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
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	waitTimeSeconds          = 20
	messageBatchSize         = 10
	visibilityTimeoutSeconds = 2 * waitTimeSeconds
)

var (
	logDataTypeAttributeName = "type"
	logTypeAttributeName     = "id"

	messageAttributes = []*string{
		&logDataTypeAttributeName,
		&logTypeAttributeName,
	}
)

func Requeue(sqsClient sqsiface.SQSAPI, region, fromQueueName, toQueueName string) error {
	fromQueueURL, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &fromQueueName,
	})
	if err != nil {
		return errors.Wrapf(err, "cannot find source queue %s in region %s", fromQueueName, region)
	}

	toQueueURL, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &toQueueName,
	})
	if err != nil {
		return errors.Wrapf(err, "cannot find destination queue %s in region %s", toQueueName, region)
	}

	zap.S().Debugf("Moving messages from %s to %s", fromQueueName, toQueueName)
	totalMessages := 0
	for {
		resp, err := sqsClient.ReceiveMessage(&sqs.ReceiveMessageInput{
			MessageAttributeNames: messageAttributes,
			WaitTimeSeconds:       aws.Int64(waitTimeSeconds),
			MaxNumberOfMessages:   aws.Int64(messageBatchSize),
			VisibilityTimeout:     aws.Int64(visibilityTimeoutSeconds),
			QueueUrl:              fromQueueURL.QueueUrl,
		})

		if err != nil {
			return errors.Wrapf(err, "failure receiving messages to move from %s", fromQueueName)
		}

		messages := resp.Messages
		numberOfMessages := len(messages)
		totalMessages += numberOfMessages
		if numberOfMessages == 0 {
			zap.S().Debugf("Successfully requeued %d messages.", totalMessages)
			return nil
		}

		zap.S().Debugf("Moving %d message(s)...", numberOfMessages)

		var sendMessageBatchRequestEntries []*sqs.SendMessageBatchRequestEntry
		for index, element := range messages {
			sendMessageBatchRequestEntries = append(sendMessageBatchRequestEntries, &sqs.SendMessageBatchRequestEntry{
				Id:                aws.String(strconv.Itoa(index)),
				MessageBody:       element.Body,
				MessageAttributes: element.MessageAttributes,
			})
		}

		_, err = sqsClient.SendMessageBatch(&sqs.SendMessageBatchInput{
			Entries:  sendMessageBatchRequestEntries,
			QueueUrl: toQueueURL.QueueUrl,
		})
		if err != nil {
			return errors.Wrapf(err, "failure moving messages to %s", toQueueName)
		}

		var deleteMessageBatchRequestEntries []*sqs.DeleteMessageBatchRequestEntry
		for index, element := range messages {
			deleteMessageBatchRequestEntries = append(deleteMessageBatchRequestEntries, &sqs.DeleteMessageBatchRequestEntry{
				Id:            aws.String(strconv.Itoa(index)),
				ReceiptHandle: element.ReceiptHandle,
			})
		}

		_, err = sqsClient.DeleteMessageBatch(&sqs.DeleteMessageBatchInput{
			Entries:  deleteMessageBatchRequestEntries,
			QueueUrl: fromQueueURL.QueueUrl,
		})
		if err != nil {
			return errors.Wrapf(err, "failure deleting moved messages from %s", fromQueueName)
		}
	}
}
