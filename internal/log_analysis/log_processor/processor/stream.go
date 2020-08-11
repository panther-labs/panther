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
	"runtime"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
)

const (
	processingMaxFilesLimit   = 5000 // limit this so there is time to delete from the queue at the end
	processingTimeLimitScalar = 0.5  // the processing runtime should be shorter than lambda timeout to make room to flush buffers

	sqsMaxBatchSize    = 10 // max messages per read for SQS (can't find an sqs constant to refer to)
	sqsWaitTimeSeconds = 20 //  note: 20 is max for sqs
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

// entry point for unit testing, pass in read/process functions
func streamEvents(sqsClient sqsiface.SQSAPI, deadlineTime time.Time, event events.SQSEvent,
	processFunc func(chan *common.DataStream, destinations.Destination) error,
	generateDataStreamsFunc func([]string) ([]*common.DataStream, error)) (int, error) {

	// these cannot be named return vars because it would cause a data race
	var sqsMessageCount int
	var err error

	streamChan := make(chan *common.DataStream, 2*sqsMaxBatchSize) // use small buffer to pipeline events
	processingDeadlineTime := deadlineTime.Add(-time.Duration(float32(time.Since(deadlineTime)) * processingTimeLimitScalar))

	var accumulatedMessageReceipts []*string // accumulate message receipts for delete at the end

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

		// continue to read until either there are no sqs messages or we have exceeded the processing time/file limit
		highMemoryCounter := 0
		for isProcessingTimeRemaining(processingDeadlineTime) && len(accumulatedMessageReceipts) < processingMaxFilesLimit {
			// if we push too fast we can oom
			if heapUsedMB, memAvailableMB, isHigh := highMemoryUsage(); isHigh {
				if highMemoryCounter%100 == 0 { // limit logging
					zap.L().Warn("high memory usage",
						zap.Float32("heapUsedDB", heapUsedMB),
						zap.Float32("memAvailableDB", memAvailableMB),
						zap.Int("sqsMessagesRead", len(accumulatedMessageReceipts)))
				}
				time.Sleep(time.Second)
				highMemoryCounter++
				continue
			}

			// under low load we do not read from the sqs queue and just exit
			numberOfQueuedMessages, err := queueDepth(sqsClient)
			if err != nil {
				readEventErrorChan <- err
				return
			}
			if numberOfQueuedMessages == 0 {
				break
			}

			// keep reading from SQS to maximize output aggregation
			messages, messageReceipts, err := sqsbatch.ReceiveMessage(sqsClient, common.Config.SqsQueueURL, sqsWaitTimeSeconds)
			if err != nil {
				readEventErrorChan <- err
				return
			}

			if len(messages) == 0 { // no work OR reached the max sqs messages allowed in flight, either way need to break
				break
			}

			// remember so we can delete when done
			accumulatedMessageReceipts = append(accumulatedMessageReceipts, messageReceipts...)

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

	// Use a properly configured JSON API for Athena quirks
	jsonAPI := common.BuildJSON()
	registeredLogTypes := registry.Default()
	// process streamChan until closed (blocks)
	err = processFunc(streamChan, destinations.CreateS3Destination(registeredLogTypes, jsonAPI))
	if err != nil { // prefer Process() error to readEventError
		return 0, err
	}
	readEventError := <-readEventErrorChan
	if readEventError != nil {
		return 0, readEventError
	}

	// delete messages from sqs q on success (best effort)
	sqsbatch.DeleteMessageBatch(sqsClient, common.Config.SqsQueueURL, accumulatedMessageReceipts)
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

func highMemoryUsage() (heapUsedMB, memAvailableMB float32, isHigh bool) {
	const (
		threshold  = 0.8
		bytesPerMB = 1024 * 1024
	)
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	// NOTE: HeapAlloc is used because it tracks memory release better/faster than Sys
	heapUsedMB = float32(memStats.HeapAlloc / bytesPerMB)
	memAvailableMB = float32(common.Config.AwsLambdaFunctionMemorySize)
	return heapUsedMB, memAvailableMB, heapUsedMB/memAvailableMB > threshold
}
