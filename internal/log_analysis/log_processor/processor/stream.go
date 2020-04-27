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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
)

const (
	processingTimeLimitScalar = 0.8 // the processing runtime should be shorter than lambda timeout to make room to flush buffers

	sqsMaxBatchSize    = 10 // max messages per read for SQS (can't find an sqs constant to refer to)
	sqsWaitTimeSeconds = 20 // long wait, this handles slow event trickles (20 is max for sqs, can't find an sqs constant to refer to)
)

var (
	// how many times to read nothing in a row before stopping lambda (var for tests)
	maxContiguousEmptyReads = 10 // this has a consequence of making the min lambda time sqsWaitTimeSeconds*maxContiguousEmptyReads
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

		numberContiguousEmptyReads := 0 // count contiguous empty sqs reads

		// continue to read until either there are no sqs messages for a time or we have exceeded the processing time limit
		for time.Since(startTime) < processingTimeLimit {
			for _, dataStream := range dataStreams {
				streamChan <- dataStream
			}

			// keep reading from SQS to maximize output aggregation
			overLimit, receiveMessageOutput, err := readSqsMessages(sqsClient)
			if err != nil {
				readEventErrorChan <- err
				return
			}

			// just stop processing if the queue has too many requests in flight (and delete from queue)
			// https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
			if overLimit {
				zap.L().Warn("sqs queue has too many messages in-flight, stopping reading new messages and finishing processing",
					zap.String("guidance", "considering increasing the size of the log processor lambda in panther_config.yml"),
					zap.String("queueURL", common.Config.SqsQueueURL))
				break
			}

			if len(receiveMessageOutput.Messages) == 0 {
				numberContiguousEmptyReads++
				if numberContiguousEmptyReads >= maxContiguousEmptyReads {
					break
				}
				continue
			}
			numberContiguousEmptyReads = 0 // reset, messages read

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

func readSqsMessages(sqsClient sqsiface.SQSAPI) (overLimit bool, receiveMessageOutput *sqs.ReceiveMessageOutput, err error) {
	receiveMessageOutput, err = sqsClient.ReceiveMessage(&sqs.ReceiveMessageInput{
		WaitTimeSeconds:     aws.Int64(sqsWaitTimeSeconds), // wait this long UNLESS MaxNumberOfMessages read
		MaxNumberOfMessages: aws.Int64(sqsMaxBatchSize),    // max size allowed
		VisibilityTimeout:   &common.Config.TimeLimitSec,
		QueueUrl:            &common.Config.SqsQueueURL,
	})
	if err != nil {
		// in the case of sqs.ErrCodeOverLimit we just tell caller, no error
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == sqs.ErrCodeOverLimit {
			return true, receiveMessageOutput, nil
		}
		err = errors.Wrapf(err, "failure receiving messages from %s", common.Config.SqsQueueURL)
		return false, receiveMessageOutput, err
	}

	return false, receiveMessageOutput, err
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
