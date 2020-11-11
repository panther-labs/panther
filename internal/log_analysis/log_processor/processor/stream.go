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
	"context"
	"runtime"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
)

const (
	// Limit this so there is time to delete from the queue at the end.
	processingMaxFilesLimit = 5000

	// The max messages per read for SQS (can't find an sqs constant to refer to).
	sqsMaxBatchSize = 10
)

/*
PollEvents acts as an interface to aggregate sqs messages to avoid many small S3 files being created under load.
The function will attempt to read more messages from the queue when the queue has messages. Under load
the lambda will continue to read events and maximally aggregate data to produce fewer, bigger files.
Fewer, bigger files makes Athena queries much faster.
*/
func PollEvents(
	ctx context.Context,
	sqsClient sqsiface.SQSAPI,
	resolver logtypes.Resolver,
) (sqsMessageCount int, err error) {

	newProcessor := NewFactory(resolver)
	process := func(streams <-chan *common.DataStream, dest destinations.Destination) error {
		return Process(streams, dest, newProcessor)
	}
	return pollEvents(ctx, sqsClient, process, sources.ReadSnsMessage)
}

// entry point for unit testing, pass in read/process functions
func pollEvents(
	ctx context.Context,
	sqsClient sqsiface.SQSAPI,
	processFunc ProcessFunc,
	generateDataStreamsFunc func(string) ([]*common.DataStream, error)) (int, error) {

	streamChan := make(chan *common.DataStream, 2*sqsMaxBatchSize) // use small buffer to pipeline events
	var accumulatedMessageReceipts []*string                       // accumulate message receipts for delete at the end

	readEventErrorChan := make(chan error, 1) // below go routine closes over this for errors, 1 deep buffer
	go func() {
		defer func() {
			close(streamChan)         // done reading messages, this will cause processFunc() to return
			close(readEventErrorChan) // no more writes on err chan
		}()

		// continue to read until either there are no sqs messages or we have exceeded the processing time/file limit
		highMemoryCounter := 0
		for len(accumulatedMessageReceipts) < processingMaxFilesLimit {
			select {
			case <-ctx.Done():
				return
			default:
				// Makes select non blocking
			}

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
			// keep reading from SQS to maximize output aggregation
			messages, err := receiveFromSqs(ctx, sqsClient)
			if err != nil {
				readEventErrorChan <- err
				return
			}

			if len(messages) == 0 { // no work to do but maybe more later OR reached the max sqs messages allowed in flight, either way need to break
				break
			}

			for _, msg := range messages {
				dataStreams, err := generateDataStreamsFunc(aws.StringValue(msg.Body))
				if err != nil {
					readEventErrorChan <- err
					return
				}
				for _, dataStream := range dataStreams {
					streamChan <- dataStream
				}

				accumulatedMessageReceipts = append(accumulatedMessageReceipts, msg.ReceiptHandle)
			}
		}
	}()

	// Use a properly configured JSON API for Athena quirks
	jsonAPI := common.ConfigForDataLakeWriters()
	// process streamChan until closed (blocks)
	dest := destinations.CreateS3Destination(jsonAPI)
	if err := processFunc(streamChan, dest); err != nil {
		return 0, err
	}
	readEventError := <-readEventErrorChan
	if readEventError != nil {
		return 0, readEventError
	}

	// delete messages from sqs q on success (best effort)
	sqsbatch.DeleteMessageBatch(sqsClient, common.Config.SqsQueueURL, accumulatedMessageReceipts)
	return len(accumulatedMessageReceipts), nil
}

func getQueueIntegerAttribute(attrs map[string]*string, attr string) (count int, err error) {
	intAsStringPtr := attrs[attr]
	if intAsStringPtr == nil {
		err = errors.Errorf("failure getting %s count from %s", attr, common.Config.SqsQueueURL)
		return 0, err
	}
	count, err = strconv.Atoi(*intAsStringPtr)
	if err != nil {
		err = errors.Wrapf(err, "failure reading %s (%s) count from %s", attr, *intAsStringPtr, common.Config.SqsQueueURL)
		return 0, err
	}
	return count, err
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

func receiveFromSqs(ctx context.Context, sqsClient sqsiface.SQSAPI) ([]*sqs.Message, error) {
	request := &sqs.ReceiveMessageInput{
		WaitTimeSeconds:     aws.Int64(0),
		MaxNumberOfMessages: aws.Int64(sqsMaxBatchSize),
		QueueUrl:            &common.Config.SqsQueueURL,
	}
	receiveMessageOutput, err := sqsClient.ReceiveMessageWithContext(ctx, request)

	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		err = errors.Wrapf(err, "failure receiving messages from %s", common.Config.SqsQueueURL)
		return nil, err
	}

	return receiveMessageOutput.Messages, nil
}
