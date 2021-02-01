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
	err = Requeue(sqsClient, *awsSession.Config.Region, fromq, toq)
	require.NoError(t, err)

	// check
	numberMovedMessages, numberMovedMessagesWithAttrs, err := testutils.CountMessagesInQueue(sqsClient, toq,
		messageBatchSize, visibilityTimeoutSeconds)
	assert.NoError(t, err)
	assert.Equal(t, numberTestMessages, numberMovedMessages)
	// 1/2 will have attributes, see testutils.AddMessagesToQueue()
	assert.Equal(t, numberTestMessages/2, numberMovedMessagesWithAttrs)

	// clean up
	err = testutils.DeleteQueue(sqsClient, fromq)
	assert.NoError(t, err)
	err = testutils.DeleteQueue(sqsClient, toq)
	assert.NoError(t, err)
}
