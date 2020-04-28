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

	sqsMaxBatchSize       = 10              // max messages per read for SQS (can't find an sqs constant to refer to)
	sqsWaitTimeSeconds    = 20              //  note: 20 is max for sqs
	sqsQueueSizeThreshold = sqsMaxBatchSize // above this will trigger reading from the queue directly to improve aggregation
)

/*
StreamEvents acts as an interface to aggregate sqs messages to avoid many small S3 files being created under load.
The function will attempt to read more messages from the queue when the queue has messages. Under load
the lambda will continue to read events and maximally aggregate data to produce fewer, bigger files.
Fewer, bigger files makes Athena queries much faster.
*/
func StreamEvents(sqsClient sqsiface.SQSAPI, deadlineTime time.Time, event events.SQSEvent) (sqsMessageCount int, err error) {
	return streamEvents(sqsClient, deadlineTime, event, Process, sources.ReadSnsMessages)
}

type messageReceiptSet = [][]*string

// entry point for unit testing, pass in read/process functions
func streamEvents(sqsClient sqsiface.SQSAPI, deadlineTime time.Time, event events.SQSEvent,
	processFunc func(chan *common.DataStream, destinations.Destination) error,
	generateDataStreamsFunc func([]string) ([]*common.DataStream, error)) (int, error) {

	// these cannot be named return vars because it would cause a data race
	var sqsMessageCount int
	var err error

	streamChan := make(chan *common.DataStream, 2*sqsMaxBatchSize) // use small buffer to pipeline events
	processingDeadlineTime := deadlineTime.Add(-time.Duration(float32(time.Since(deadlineTime)) * processingTimeLimitScalar))

	var messageReceiptSets messageReceiptSet // accumulate message receipts for delete at the end

	readEventErrorChan := make(chan error, 1) // below go routine closes over this for errors, 1 deep buffer
	go func() {
		defer func() {
			close(streamChan)         // done reading messages, this will cause processFunc() to return
			close(readEventErrorChan) // no more writes on err chan
		}()

		// extract first set of messages from the lambda call, lambda handles delete of these
		dataStreams, err := lambdaDataStreams(event, generateDataStreamsFunc)
		if err != nil {
			readEventErrorChan <- err
			return
		}

		// process lambda events
		sqsMessageCount += len(dataStreams)
		for _, dataStream := range dataStreams {
			streamChan <- dataStream
		}

		// continue to read until either there are no sqs messages or we have exceeded the processing time limit
		for isProcessingTimeRemaining(processingDeadlineTime) {
			// under low load we do not read from the sqs queue and just exit
			numberOfQueuedMessages, err := queueDepth(sqsClient)
			if err != nil {
				readEventErrorChan <- err
				return
			}
			if numberOfQueuedMessages < sqsQueueSizeThreshold {
				break
			}

			// keep reading from SQS to maximize output aggregation
			messages, messageReceipts, overLimit, err := readSqsMessages(sqsClient)
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

			if len(messages) == 0 { // no more work
				break
			}

			// remember so we can delete when done
			messageReceiptSets = append(messageReceiptSets, messageReceipts)

			// extract from sqs read responses
			dataStreams, err = sqsDataStreams(messages, generateDataStreamsFunc)
			if err != nil {
				readEventErrorChan <- err
				return
			}

			// process sqs messages
			sqsMessageCount += len(dataStreams)
			for _, dataStream := range dataStreams {
				streamChan <- dataStream
			}
		}
	}()

	// process streamChan until closed (blocks)
	err = processFunc(streamChan, destinations.CreateS3Destination())
	if err != nil { // prefer Process() error to readEventError
		return 0, err
	}
	readEventError := <-readEventErrorChan
	if readEventError != nil {
		return 0, readEventError
	}

	// delete messages from sqs q on success (best effort)
	deleteSqsMessages(sqsClient, messageReceiptSets)
	return sqsMessageCount, nil
}

func lambdaDataStreams(event events.SQSEvent,
	readSnsMessagesFunc func([]string) ([]*common.DataStream, error)) ([]*common.DataStream, error) {

	eventMessages := make([]string, len(event.Records))
	for i, record := range event.Records {
		eventMessages[i] = record.Body
	}
	return readSnsMessagesFunc(eventMessages)
}

func isProcessingTimeRemaining(deadline time.Time) bool {
	return time.Since(deadline) < 0 // deadline is in future, will be positive once passed
}

func sqsDataStreams(messages []*sqs.Message,
	readSnsMessagesFunc func([]string) ([]*common.DataStream, error)) ([]*common.DataStream, error) {

	eventMessages := make([]string, len(messages))
	for i, message := range messages {
		eventMessages[i] = *message.Body
	}
	return readSnsMessagesFunc(eventMessages)
}

func readSqsMessages(sqsClient sqsiface.SQSAPI) (messages []*sqs.Message, messageReceipts []*string, overLimit bool, err error) {
	receiveMessageOutput, err := sqsClient.ReceiveMessage(&sqs.ReceiveMessageInput{
		WaitTimeSeconds:     aws.Int64(sqsWaitTimeSeconds), // wait this long UNLESS MaxNumberOfMessages read
		MaxNumberOfMessages: aws.Int64(sqsMaxBatchSize),    // max size allowed
		QueueUrl:            &common.Config.SqsQueueURL,
	})
	if err != nil {
		// in the case of sqs.ErrCodeOverLimit we just tell caller, no error
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == sqs.ErrCodeOverLimit {
			return nil, nil, true, nil
		}
		err = errors.Wrapf(err, "failure receiving messages from %s", common.Config.SqsQueueURL)
		return nil, nil, false, err
	}

	messageReceipts = make([]*string, len(receiveMessageOutput.Messages))
	for i := range receiveMessageOutput.Messages {
		messageReceipts[i] = receiveMessageOutput.Messages[i].ReceiptHandle
	}

	return receiveMessageOutput.Messages, messageReceipts, false, err
}

func deleteSqsMessages(sqsClient sqsiface.SQSAPI, messageReceiptSets messageReceiptSet) {
	messageReceiptChan := make(chan *string, sqsMaxBatchSize)
	go func() {
		for _, messageReceipts := range messageReceiptSets {
			for _, messageReceipt := range messageReceipts {
				messageReceiptChan <- messageReceipt
			}
		}
		close(messageReceiptChan) // tells streamDeleteSqsMessages() we are done
	}()

	streamDeleteSqsMessages(sqsClient, messageReceiptChan) // blocks until done
}

func streamDeleteSqsMessages(sqsClient sqsiface.SQSAPI, messageReceiptChan chan *string) {
	// pre-allocate space
	deleteMessageBatchRequestEntries := make([]*sqs.DeleteMessageBatchRequestEntry, sqsMaxBatchSize)
	batchCounter := 0
	for i := range deleteMessageBatchRequestEntries {
		deleteMessageBatchRequestEntries[i] = &sqs.DeleteMessageBatchRequestEntry{
			Id: aws.String(strconv.Itoa(i)), // preset ids within batch
		}
	}

	for messageReceipt := range messageReceiptChan {
		deleteMessageBatchRequestEntries = deleteMessageBatchRequestEntries[:batchCounter+1] // extend
		deleteMessageBatchRequestEntries[batchCounter].ReceiptHandle = messageReceipt        // set
		batchCounter++
		if batchCounter == sqsMaxBatchSize {
			batchDeleteSqsMessages(sqsClient, deleteMessageBatchRequestEntries)
			// reset
			batchCounter = 0
			deleteMessageBatchRequestEntries = deleteMessageBatchRequestEntries[:0]
		}
	}
	// the rest
	if batchCounter > 0 {
		batchDeleteSqsMessages(sqsClient, deleteMessageBatchRequestEntries)
	}
}

func batchDeleteSqsMessages(sqsClient sqsiface.SQSAPI, deleteMessageBatchRequestEntries []*sqs.DeleteMessageBatchRequestEntry) {
	// NOTE: this is a best effort, and we log any errors. Failed deleted messages will be re-processed
	deleteMessageBatchOutput, err := sqsClient.DeleteMessageBatch(&sqs.DeleteMessageBatchInput{
		Entries:  deleteMessageBatchRequestEntries,
		QueueUrl: &common.Config.SqsQueueURL,
	})
	if err != nil {
		zap.L().Error("failure deleting sqs messages",
			zap.String("guidance", "failed messages will be reprocessed"),
			zap.String("queueURL", common.Config.SqsQueueURL),
			zap.Int("numberOfFailedMessages", len(deleteMessageBatchOutput.Failed)),
			zap.Int("numberOfSuccessfulMessages", len(deleteMessageBatchOutput.Successful)),
			zap.Error(err))
	}
}

func queueDepth(sqsClient sqsiface.SQSAPI) (numberOfQueuedMessages int, err error) {
	getQueueAttributesInput := &sqs.GetQueueAttributesInput{
		AttributeNames: []*string{aws.String(sqs.QueueAttributeNameApproximateNumberOfMessages)},
		QueueUrl:       &common.Config.SqsQueueURL,
	}
	getQueueAttributesOutput, err := sqsClient.GetQueueAttributes(getQueueAttributesInput)
	if err != nil {
		err = errors.Wrapf(err, "failure getting message count from %s", common.Config.SqsQueueURL)
		return 0, err
	}
	approximateNumberOfMessages := getQueueAttributesOutput.Attributes[sqs.QueueAttributeNameApproximateNumberOfMessages]
	if approximateNumberOfMessages == nil {
		err = errors.Errorf("failure getting %s count from %s",
			sqs.QueueAttributeNameApproximateNumberOfMessages, common.Config.SqsQueueURL)
		return 0, err
	}
	numberOfQueuedMessages, err = strconv.Atoi(*approximateNumberOfMessages)
	if err != nil {
		err = errors.Wrapf(err, "failure reading %s (%s) count from %s",
			sqs.QueueAttributeNameApproximateNumberOfMessages, *approximateNumberOfMessages, common.Config.SqsQueueURL)
		return 0, err
	}
	return numberOfQueuedMessages, err
}
