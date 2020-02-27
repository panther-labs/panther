package requeue

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	queuePrefix = "panther-test-requeue"
)

var (
	integrationTest bool
	awsSession      *session.Session
	sqsClient       *sqs.SQS
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		awsSession = session.Must(session.NewSession())
		sqsClient = sqs.New(awsSession)
	}
	os.Exit(m.Run())
}

func TestIntegrationRequeue(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	const numberTestBatches = 3
	const numberTestMessages = numberTestBatches * messageBatchSize
	var err error

	// make 2 queues to move things between
	fromq := queuePrefix + "-from"
	toq := queuePrefix + "-toq"
	// delete first in case these were left from previous failed test (best effort)
	deletedQueue := false
	err = deleteQueue(fromq)
	if err == nil {
		deletedQueue = true
	}
	err = deleteQueue(toq)
	if err == nil {
		deletedQueue = true
	}
	if deletedQueue {
		// you have to wait 60+ seconds to use a q that has been deleted
		time.Sleep(time.Second * 61)
	}
	err = createQueue(fromq)
	require.NoError(t, err)
	err = createQueue(toq)
	require.NoError(t, err)

	// add some messages to fromq
	err = addQueue(fromq, numberTestBatches)
	require.NoError(t, err)

	// move them to toq
	err = Requeue(sqsClient, fromq, toq)
	require.NoError(t, err)

	// check
	numberMovedMessages, err := countQueue(toq)
	assert.NoError(t, err)
	assert.Equal(t, numberTestMessages, numberMovedMessages)

	// clean up
	err = deleteQueue(fromq)
	assert.NoError(t, err)
	err = deleteQueue(toq)
	assert.NoError(t, err)
}

func deleteQueue(qname string) (err error) {
	deleteQueueURL, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &qname,
	})
	if err != nil {
		return errors.Wrapf(err, "cannot get delete queue url for %s", qname)
	}
	_, err = sqsClient.DeleteQueue(&sqs.DeleteQueueInput{
		QueueUrl: deleteQueueURL.QueueUrl,
	})
	return err
}

func createQueue(qname string) (err error) {
	_, err = sqsClient.CreateQueue(&sqs.CreateQueueInput{
		QueueName: &qname,
	})
	return err
}

func addQueue(qname string, nBatches int) (err error) {
	addQueueURL, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
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

		_, err = sqsClient.SendMessageBatch(&sqs.SendMessageBatchInput{
			Entries:  sendMessageBatchRequestEntries,
			QueueUrl: addQueueURL.QueueUrl,
		})
		if err != nil {
			return errors.Wrap(err, "failure sending test messages")
		}
	}

	return nil
}

func countQueue(qname string) (totalMessages int, err error) {
	countQueueURL, err := sqsClient.GetQueueUrl(&sqs.GetQueueUrlInput{
		QueueName: &qname,
	})
	if err != nil {
		return 0, errors.Wrapf(err, "cannot get count queue url for %s", qname)
	}

	// drain the queue, counting
	for {
		resp, err := sqsClient.ReceiveMessage(&sqs.ReceiveMessageInput{
			MaxNumberOfMessages: aws.Int64(messageBatchSize),
			VisibilityTimeout:   aws.Int64(visibilityTimeout),
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
