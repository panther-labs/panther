package processor

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
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
)

// reads lambda event, then continues to read events from sqs q
func StreamEvents(startTime time.Time, event events.SQSEvent) (sqsMessageCount int, err error) {
	streamChan := make(chan *common.DataStream, 20) // small buffer to get concurrency

	// maximum run time for lambda
	lambdaTimeLimitSec, err := strconv.Atoi(os.Getenv("TIME_LIMIT_SEC"))
	if err != nil {
		err = errors.Wrapf(err, "cannot get env var TIME_LIMIT_SEC")
		return sqsMessageCount, err
	}
	const timeLimitScalar = 0.8 // runtime should be shorter than lambda timeout to make room to flush buffers
	timeLimit := time.Second * time.Duration(float32(lambdaTimeLimitSec)*timeLimitScalar)

	queueURL := os.Getenv("SQS_QUEUE_URL")
	if queueURL == "" {
		err = errors.Errorf("cannot get env var SQS_QUEUE_URL")
		return sqsMessageCount, err
	}

	sqsClient := sqs.New(common.Session)

	var sqsResponses []*sqs.ReceiveMessageOutput // accumulate responses for delete at the end

	var readEventError error
	go func() {
		defer close(streamChan) // done reading messages

		// collect first set of messages from the lambda call, lambda handles delete of these
		eventMessages := make([]string, len(event.Records))
		for i, record := range event.Records {
			sqsMessageCount++
			eventMessages[i] = record.Body
		}
		dataStreams, err := sources.ReadSnsMessages(eventMessages)
		if err != nil {
			readEventError = err
			return
		}

		for time.Since(startTime) < timeLimit {
			for _, dataStream := range dataStreams {
				streamChan <- dataStream
			}

			// keep reading from SQS to avoid lambda calls and maximize output aggregation
			var receiveMessageOutput *sqs.ReceiveMessageOutput
			receiveMessageOutput, readEventError = sqsClient.ReceiveMessage(&sqs.ReceiveMessageInput{
				WaitTimeSeconds:     aws.Int64(15), // wait a bit for more messages
				MaxNumberOfMessages: aws.Int64(10), // max size allowed
				VisibilityTimeout:   aws.Int64(int64(lambdaTimeLimitSec)),
				QueueUrl:            &queueURL,
			})
			if readEventError != nil {
				readEventError = errors.Wrapf(err, "failure reading messages from %s", queueURL)
				return
			}

			if len(receiveMessageOutput.Messages) == 0 { // no more work to do
				break
			}

			// remember so we can delete
			sqsResponses = append(sqsResponses, receiveMessageOutput)

			// extract
			eventMessages := make([]string, len(receiveMessageOutput.Messages))
			for i, message := range receiveMessageOutput.Messages {
				sqsMessageCount++
				eventMessages[i] = *message.Body
			}
			dataStreams, readEventError = sources.ReadSnsMessages(eventMessages)
			if readEventError != nil {
				return
			}
		}
	}()

	// process streamChan until closed (blocks)
	err = Process(streamChan, destinations.CreateDestination())
	if err != nil { // prefer Process() error to readEventError
		return sqsMessageCount, err
	}
	if readEventError != nil {
		return sqsMessageCount, readEventError
	}

	// delete messages from sqs q
	for _, sqsResponse := range sqsResponses {
		var deleteMessageBatchRequestEntries []*sqs.DeleteMessageBatchRequestEntry
		for index, msg := range sqsResponse.Messages {
			deleteMessageBatchRequestEntries = append(deleteMessageBatchRequestEntries, &sqs.DeleteMessageBatchRequestEntry{
				Id:            aws.String(strconv.Itoa(index)),
				ReceiptHandle: msg.ReceiptHandle,
			})
		}

		_, err = sqsClient.DeleteMessageBatch(&sqs.DeleteMessageBatchInput{
			Entries:  deleteMessageBatchRequestEntries,
			QueueUrl: &queueURL,
		})
		if err != nil {
			err = errors.Wrapf(err, "failure deleting messages from %s", queueURL)
			return sqsMessageCount, err
		}
	}

	return sqsMessageCount, err
}
