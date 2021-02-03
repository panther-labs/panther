package testutils

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
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
)

var (
	logDataTypeAttributeName = "type"
	logTypeAttributeName     = "id"
)

func CreateTopic(client snsiface.SNSAPI, topic string) (output *sns.CreateTopicOutput, err error) {
	output, err = client.CreateTopic(&sns.CreateTopicInput{
		Name:       &topic,
		Attributes: nil,
	})
	return output, err
}

func DeleteTopic(client snsiface.SNSAPI, topicArn string) (err error) {
	_, err = client.DeleteTopic(&sns.DeleteTopicInput{
		TopicArn: &topicArn,
	})
	return err
}

func CreateQueue(client sqsiface.SQSAPI, qname string) (err error) {
	_, err = client.CreateQueue(&sqs.CreateQueueInput{
		QueueName: &qname,
	})
	return err
}

func DeleteQueue(client sqsiface.SQSAPI, qname string) (err error) {
	deleteQueueURL, err := client.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &qname,
	})
	if err != nil {
		return errors.Wrapf(err, "cannot get delete queue url for %s", qname)
	}
	_, err = client.DeleteQueue(&sqs.DeleteQueueInput{
		QueueUrl: deleteQueueURL.QueueUrl,
	})
	return err
}

func CountMessagesInQueue(client sqsiface.SQSAPI, qname string,
	messageBatchSize, visibilityTimeoutSeconds int64) (totalMessages, totalMessagesWithAttrs int, err error) {

	countQueueURL, err := client.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &qname,
	})
	if err != nil {
		return 0, 0, errors.Wrapf(err, "cannot get count queue url for %s", qname)
	}

	// used by Panther
	messageAttributes := []*string{
		&logDataTypeAttributeName,
		&logTypeAttributeName,
	}

	// drain the queue, counting
	for {
		resp, err := client.ReceiveMessage(&sqs.ReceiveMessageInput{
			MessageAttributeNames: messageAttributes,
			MaxNumberOfMessages:   aws.Int64(messageBatchSize),
			VisibilityTimeout:     aws.Int64(visibilityTimeoutSeconds),
			QueueUrl:              countQueueURL.QueueUrl,
		})

		if err != nil {
			return 0, 0, errors.Wrap(err, qname)
		}

		totalMessages += len(resp.Messages)

		for _, message := range resp.Messages {
			if message.MessageAttributes != nil {
				totalMessagesWithAttrs++
			}
		}

		if len(resp.Messages) == 0 {
			return totalMessages, totalMessagesWithAttrs, nil
		}
	}
}

func AddMessagesToQueue(client sqsiface.SQSAPI, qname string, nBatches, messageBatchSize int) (err error) {
	addQueueURL, err := client.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &qname,
	})
	if err != nil {
		return errors.Wrapf(err, "cannot get add queue url for %s", qname)
	}

	for batch := 0; batch < nBatches; batch++ {
		var sendMessageBatchRequestEntries []*sqs.SendMessageBatchRequestEntry
		for i := 0; i < messageBatchSize; i++ {
			// give every other one some panther message attrs, ensure passing these work
			var messageAttributes map[string]*sqs.MessageAttributeValue
			if i%2 == 0 {
				messageAttributes = map[string]*sqs.MessageAttributeValue{
					logDataTypeAttributeName: {
						StringValue: aws.String("LogData"),
						DataType:    aws.String("String"),
					},
					logTypeAttributeName: {
						StringValue: aws.String("AWS.CloudTrail"),
						DataType:    aws.String("String"),
					},
				}
			}
			id := aws.String(strconv.Itoa(i))
			sendMessageBatchRequestEntries = append(sendMessageBatchRequestEntries, &sqs.SendMessageBatchRequestEntry{
				Id:                id,
				MessageBody:       id,
				MessageAttributes: messageAttributes,
			})
		}

		_, err = client.SendMessageBatch(&sqs.SendMessageBatchInput{
			Entries:  sendMessageBatchRequestEntries,
			QueueUrl: addQueueURL.QueueUrl,
		})
		if err != nil {
			return errors.Wrap(err, "failure sending test messages")
		}
	}

	return nil
}

func CountObjectsInBucket(client s3iface.S3API, bucket, prefix string) (count int, err error) {
	input := &s3.ListObjectsV2Input{
		Bucket: &bucket,
		Prefix: &prefix,
	}
	err = client.ListObjectsV2Pages(input,
		func(page *s3.ListObjectsV2Output, lastPage bool) bool {
			count += len(page.Contents)
			return true
		})
	return count, err
}
