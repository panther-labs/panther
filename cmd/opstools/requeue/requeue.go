package requeue

import (
	"log"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
)

const (
	waitTimeSeconds   = 20
	messageBatchSize  = 10
	visibilityTimeout = 20
)

func Requeue(sqsClient sqsiface.SQSAPI, fromq, toq string) error {
	fromQueueURL, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &fromq,
	})
	if err != nil {
		return errors.Wrapf(err, "cannot get source queue url for %s", fromq)
	}

	toQueueURL, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &toq,
	})
	if err != nil {
		return errors.Wrapf(err, "cannot get destination queue url for %s", toq)
	}

	log.Printf("Moving messages from %s to %s", fromq, toq)
	totalMessages := 0
	for {
		resp, err := sqsClient.ReceiveMessage(&sqs.ReceiveMessageInput{
			WaitTimeSeconds:     aws.Int64(waitTimeSeconds),
			MaxNumberOfMessages: aws.Int64(messageBatchSize),
			VisibilityTimeout:   aws.Int64(visibilityTimeout),
			QueueUrl:            fromQueueURL.QueueUrl,
		})

		if err != nil {
			return errors.Wrapf(err, "failure receiving messages to move from %s", fromq)
		}

		messages := resp.Messages
		numberOfMessages := len(messages)
		totalMessages += numberOfMessages
		if numberOfMessages == 0 {
			log.Printf("Successfully requeued %d messages.", totalMessages)
			return nil
		}

		log.Printf("Moving %d message(s)...", numberOfMessages)

		var sendMessageBatchRequestEntries []*sqs.SendMessageBatchRequestEntry
		for index, element := range messages {
			sendMessageBatchRequestEntries = append(sendMessageBatchRequestEntries, &sqs.SendMessageBatchRequestEntry{
				Id:          aws.String(strconv.Itoa(index)),
				MessageBody: element.Body,
			})
		}

		_, err = sqsClient.SendMessageBatch(&sqs.SendMessageBatchInput{
			Entries:  sendMessageBatchRequestEntries,
			QueueUrl: toQueueURL.QueueUrl,
		})
		if err != nil {
			return errors.Wrapf(err, "failure moving messages to %s", toq)
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
			return errors.Wrapf(err, "failure deleting moved messages from %s", fromq)
		}
	}
}
