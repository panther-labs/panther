package testutils

import (
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
)

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
	messageBatchSize, visibilityTimeoutSeconds int64) (totalMessages int, err error) {

	countQueueURL, err := client.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &qname,
	})
	if err != nil {
		return 0, errors.Wrapf(err, "cannot get count queue url for %s", qname)
	}

	// drain the queue, counting
	for {
		resp, err := client.ReceiveMessage(&sqs.ReceiveMessageInput{
			MaxNumberOfMessages: aws.Int64(messageBatchSize),
			VisibilityTimeout:   aws.Int64(visibilityTimeoutSeconds),
			QueueUrl:            countQueueURL.QueueUrl,
		})

		if err != nil {
			return 0, errors.Wrap(err, qname)
		}

		totalMessages += len(resp.Messages)
		if len(resp.Messages) == 0 {
			return totalMessages, nil
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
			id := aws.String(strconv.Itoa(i))
			sendMessageBatchRequestEntries = append(sendMessageBatchRequestEntries, &sqs.SendMessageBatchRequestEntry{
				Id:          id,
				MessageBody: id,
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
