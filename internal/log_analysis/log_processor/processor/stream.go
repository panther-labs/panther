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

const (
	processingTimeLimitScalar = 0.8 // the processing runtime should be shorter than lambda timeout to make room to flush buffers
)

// reads lambda event, then continues to read events from sqs q
func StreamEvents(sqsClient sqsiface.SQSAPI, startTime time.Time, event events.SQSEvent) (sqsMessageCount int, err error) {
	return streamEvents(sqsClient, startTime, event, Process, sources.ReadSnsMessages)
}

// entry point for unit testing, pass in read/process functions
func streamEvents(sqsClient sqsiface.SQSAPI, startTime time.Time, event events.SQSEvent,
	processFunc func(chan *common.DataStream, destinations.Destination) error,
	readSnsMessagesFunc func([]string) ([]*common.DataStream, error)) (int, error) {

	// these cannot be named return vars because it would cause a data race
	var sqsMessageCount int
	var err error

	streamChan := make(chan *common.DataStream, 20) // use small buffer to pipeline events
	processingTimeLimit := time.Second * time.Duration(float32(common.Config.TimeLimitSec)*processingTimeLimitScalar)

	var sqsResponses []*sqs.ReceiveMessageOutput // accumulate responses for delete at the end

	readEventErrorChan := make(chan error, 1) // below go routine closes over this for errors
	go func() {
		defer close(streamChan) // done reading messages, this will cause processFunc() to return

		// extract first set of messages from the lambda call, lambda handles delete of these
		eventMessages := make([]string, len(event.Records))
		for i, record := range event.Records {
			sqsMessageCount++
			eventMessages[i] = record.Body
		}
		dataStreams, err := readSnsMessagesFunc(eventMessages)
		if err != nil {
			readEventErrorChan <- err
			return
		}

		// continue to read until either there are no sqs messages or we have exceeded the processing time limit
		for time.Since(startTime) < processingTimeLimit {
			for _, dataStream := range dataStreams {
				streamChan <- dataStream
			}

			// keep reading from SQS to maximize output aggregation
			receiveMessageOutput, err := readSqsMessages(sqsClient, sqsResponses)
			if err != nil {
				readEventErrorChan <- err
				return
			}

			if len(receiveMessageOutput.Messages) == 0 { // no more work to do
				break
			}

			// remember so we can delete when done
			sqsResponses = append(sqsResponses, receiveMessageOutput)

			// extract from sqs read response
			eventMessages := make([]string, len(receiveMessageOutput.Messages))
			for i, message := range receiveMessageOutput.Messages {
				sqsMessageCount++
				eventMessages[i] = *message.Body
			}
			dataStreams, err = readSnsMessagesFunc(eventMessages)
			if err != nil {
				readEventErrorChan <- err
				return
			}
		}
	}()

	// process streamChan until closed (blocks)
	err = processFunc(streamChan, destinations.CreateS3Destination())
	if err != nil { // prefer Process() error to readEventError
		return 0, err
	}
	close(readEventErrorChan)
	readEventError := <-readEventErrorChan
	if readEventError != nil {
		return 0, readEventError
	}

	// delete messages from sqs q on success
	return sqsMessageCount, deleteSqsMessages(sqsClient, sqsResponses)
}

func readSqsMessages(sqsClient sqsiface.SQSAPI, sqsResponses []*sqs.ReceiveMessageOutput) (
	receiveMessageOutput *sqs.ReceiveMessageOutput, err error) {

	// linearly scale delay based on load estimate from len(sqsResponses), under very high load we will have 0 delay
	const waitTimeSecondsThreshold = 10
	var waitTimeSeconds = int64(waitTimeSecondsThreshold - len(sqsResponses))
	if waitTimeSeconds < 0 { // exceeded threshold, clip to 0, maximum throughput
		waitTimeSeconds = 0
	}

	receiveMessageOutput, err = sqsClient.ReceiveMessage(&sqs.ReceiveMessageInput{
		WaitTimeSeconds:     &waitTimeSeconds,
		MaxNumberOfMessages: aws.Int64(10), // max size allowed
		VisibilityTimeout:   &common.Config.TimeLimitSec,
		QueueUrl:            &common.Config.SqsQueueURL,
	})
	if err != nil {
		err = errors.Wrapf(err, "failure reading messages from %s", common.Config.SqsQueueURL)
		return receiveMessageOutput, err
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
