package s3queue

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
	"context"
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

	"github.com/panther-labs/panther/cmd/opstools"
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

	input := &Input{
		DriverInput: DriverInput{
			Logger:      opstools.MustBuildLogger(true),
			Account:     fakeAccountID,
			QueueName:   toq,
			Concurrency: concurrency,
		},
		Session:  awsSession,
		S3Path:   s3Path,
		S3Region: s3Region,
		Limit:    numberOfFiles,
	}
	err = S3Queue(context.TODO(), input)
	require.NoError(t, err)
	assert.Equal(t, numberOfFiles, (int)(input.Stats.NumFiles))

	numberSentMessages, _, err := testutils.CountMessagesInQueue(sqsClient, toq, messageBatchSize, visibilityTimeoutSeconds)
	assert.NoError(t, err)
	assert.Equal(t, numberOfFiles, numberSentMessages)

	err = testutils.DeleteQueue(sqsClient, toq)
	assert.NoError(t, err)
}
