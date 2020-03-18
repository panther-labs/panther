package requeue

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/cmd/opstools/testutils"
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
	err = testutils.DeleteQueue(sqsClient, fromq)
	if err == nil {
		deletedQueue = true
	}
	err = testutils.DeleteQueue(sqsClient, toq)
	if err == nil {
		deletedQueue = true
	}
	if deletedQueue {
		// you have to wait 60+ seconds to use a q that has been deleted
		time.Sleep(time.Second * 61)
	}
	err = testutils.CreateQueue(sqsClient, fromq)
	require.NoError(t, err)
	err = testutils.CreateQueue(sqsClient, toq)
	require.NoError(t, err)

	err = testutils.AddMessagesToQueue(sqsClient, fromq, numberTestBatches, messageBatchSize)
	require.NoError(t, err)

	// move them to toq
	err = Requeue(sqsClient, fromq, toq)
	require.NoError(t, err)

	// check
	numberMovedMessages, err := testutils.CountMessagesInQueue(sqsClient, toq, messageBatchSize, visibilityTimeoutSeconds)
	assert.NoError(t, err)
	assert.Equal(t, numberTestMessages, numberMovedMessages)

	// clean up
	err = testutils.DeleteQueue(sqsClient, fromq)
	assert.NoError(t, err)
	err = testutils.DeleteQueue(sqsClient, toq)
	assert.NoError(t, err)
}
