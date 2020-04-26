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
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
)

// reads lambda event, then continues to read events from sqs q
func StreamEvents(sqsClient sqsiface.SQSAPI, startTime time.Time, event events.SQSEvent) (sqsMessageCount int, err error) {
	return streamEvents(sqsClient, startTime, event, Process)
}

// entry point for unit testing
func streamEvents(sqsClient sqsiface.SQSAPI, startTime time.Time, event events.SQSEvent,
	processFunc func(chan *common.DataStream, destinations.Destination) error) (sqsMessageCount int, err error) {

	streamChan := make(chan *common.DataStream, 20) // small buffer to get concurrency

	const timeLimitScalar = 0.8 // runtime should be shorter than lambda timeout to make room to flush buffers
	timeLimit := time.Second * time.Duration(float32(common.Config.TimeLimitSec)*timeLimitScalar)

	var sqsResponses []*sqs.ReceiveMessageOutput // accumulate responses for delete at the end

	var readEventError error // below go routine closes over this for error
	go func() {
		defer close(streamChan) // done reading messages

		// extract first set of messages from the lambda call, lambda handles delete of these
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
			receiveMessageOutput, readEventError = readSqsMessages(sqsClient, sqsResponses)
			if readEventError != nil {
				return
			}

			if len(receiveMessageOutput.Messages) == 0 { // no more work to do
				break
			}

			// remember so we can delete when done
			sqsResponses = append(sqsResponses, receiveMessageOutput)

			// extract from sqs
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
	err = processFunc(streamChan, destinations.CreateS3Destination())
	if err != nil { // prefer Process() error to readEventError
		return sqsMessageCount, err
	}
	if readEventError != nil {
		return sqsMessageCount, readEventError
	}

	// delete messages from sqs q on success
	return sqsMessageCount, deleteSqsMessages(sqsClient, sqsResponses)
}

func readSqsMessages(sqsClient sqsiface.SQSAPI, sqsResponses []*sqs.ReceiveMessageOutput) (
	receiveMessageOutput *sqs.ReceiveMessageOutput, err error) {

	// scale delay based on load estimate from sqsResponses, user very high load we will have 0 delay
	const waitTimeSecondsThreshold = 10
	var waitTimeSeconds int64
	if len(sqsResponses) <= waitTimeSecondsThreshold { // linearly scale down sqs wait as we get repeated events
		waitTimeSeconds = int64(waitTimeSecondsThreshold - len(sqsResponses))
	}

	receiveMessageOutput, err = sqsClient.ReceiveMessage(&sqs.ReceiveMessageInput{
		WaitTimeSeconds:     aws.Int64(waitTimeSeconds),
		MaxNumberOfMessages: aws.Int64(10), // max size allowed
		VisibilityTimeout:   aws.Int64(int64(common.Config.TimeLimitSec)),
		QueueUrl:            &common.Config.SqsQueueURL,
	})
	if err != nil {
		err = errors.Wrapf(err, "failure reading messages from %s", common.Config.SqsQueueURL)
		return
	}

	return receiveMessageOutput, err
}

func deleteSqsMessages(sqsClient sqsiface.SQSAPI, sqsResponses []*sqs.ReceiveMessageOutput) (err error) {
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
			QueueUrl: &common.Config.SqsQueueURL,
		})
		if err != nil {
			err = errors.Wrapf(err, "failure deleting messages from %s", common.Config.SqsQueueURL)
			return err
		}
	}
	return err
}
