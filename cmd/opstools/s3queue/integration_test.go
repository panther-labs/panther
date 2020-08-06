package s3queue

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/cmd/opstools/testutils"
)

const (
	fakeAccountID            = "012345678912"
	queuePrefix              = "panther-test-s3queue"
	s3Path                   = "s3://panther-public-cloudformation-templates/" // this is a public Panther bucket with CF files we can use
	s3Region                 = "us-west-2"                                     // region of above bucket
	numberOfFiles            = 10                                              // we expect at least this many
	messageBatchSize         = 10
	visibilityTimeoutSeconds = 10
	concurrency              = 10
)

var (
	integrationTest bool
	awsSession      *session.Session
	s3Client        *s3.S3
	sqsClient       *sqs.SQS
)

func TestMain(m *testing.M) {
	integrationTest = strings.ToLower(os.Getenv("INTEGRATION_TEST")) == "true"
	if integrationTest {
		awsSession = session.Must(session.NewSession(aws.NewConfig().WithRegion(s3Region)))
		s3Client = s3.New(awsSession)
		sqsClient = sqs.New(awsSession)
	}
	os.Exit(m.Run())
}

func TestIntegrationS3queue(t *testing.T) {
	if !integrationTest {
		t.Skip()
	}

	var err error

	toq := queuePrefix + "-toq"
	// delete first in case these were left from previous failed test (best effort)
	deletedQueue := false
	err = testutils.DeleteQueue(sqsClient, toq)
	if err == nil {
		deletedQueue = true
	}
	if deletedQueue {
		// you have to wait 60+ seconds to use a q that has been deleted
		time.Sleep(time.Second * 61)
	}
	err = testutils.CreateQueue(sqsClient, toq)
	require.NoError(t, err)

	stats := &Stats{}
	err = S3Queue(awsSession, fakeAccountID, s3Path, s3Region, toq, concurrency, numberOfFiles, stats)
	require.NoError(t, err)
	assert.Equal(t, numberOfFiles, (int)(stats.NumFiles))

	numberSentMessages, err := testutils.CountMessagesInQueue(sqsClient, toq, messageBatchSize, visibilityTimeoutSeconds)
	assert.NoError(t, err)
	assert.Equal(t, numberOfFiles, numberSentMessages)

	err = testutils.DeleteQueue(sqsClient, toq)
	assert.NoError(t, err)
}
