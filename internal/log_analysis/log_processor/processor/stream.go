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
	"io"
	"runtime"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	logmetrics "github.com/panther-labs/panther/internal/log_analysis/log_processor/metrics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
	"github.com/panther-labs/panther/pkg/awsutils"
	"github.com/panther-labs/panther/pkg/metrics"
)

const (
	// Limit this so there is time to delete from the queue at the end.
	processingMaxFilesLimit = 5000
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
	resolver pantherlog.ParserResolver,
) (sqsMessageCount int, err error) {

	newProcessor := NewFactory(resolver)
	process := func(streams <-chan *common.DataStream, dest destinations.Destination) error {
		return Process(ctx, streams, dest, newProcessor)
	}
	return pollEvents(ctx, sqsClient, process, sources.ReadSnsMessage)
}

// entry point for unit testing, pass in read/process functions
func pollEvents(
	ctx context.Context,
	sqsClient sqsiface.SQSAPI,
	processFunc ProcessFunc,
	generateDataStreamsFunc func(context.Context, string) ([]*common.DataStream, error)) (int, error) {

	// We should poll events for 1/4 the Lambda's duration, leaving the balance for processing and flushing data
	deadline, ok := ctx.Deadline()
	if !ok {
		panic("lambda context doesn't have a deadline!")
	}
	pollingTimeout := time.Until(deadline) / 4
	pollCtx, cancel := context.WithTimeout(ctx, pollingTimeout)
	defer cancel()

	streamChan := make(chan *common.DataStream) // must be unbuffered to apply back pressure!
	var accumulatedMessageReceipts []*string    // accumulate message receipts for delete at the end

	go func() {
		defer func() {
			close(streamChan) // done reading messages, this will cause processFunc() to return
		}()

		// continue to read until either there are no sqs messages or we have exceeded the processing time/file limit
		highMemoryCounter := 0

		for len(accumulatedMessageReceipts) < processingMaxFilesLimit {
			select {
			case <-pollCtx.Done():
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
			messages, err := receiveFromSqs(pollCtx, sqsClient)
			if err != nil {
				zap.L().Error("Encountered issue while polling sqs messages. Stopping polling", zap.Error(err))
				return
			}

			if len(messages) == 0 { // no work to do but maybe more later OR reached the max sqs messages allowed in flight, either way need to break
				return
			}

			for _, msg := range messages {
				// pass lambda context to set FULL deadline to process which is pushed down into downloader
				dataStreams, err := generateDataStreamsFunc(ctx, aws.StringValue(msg.Body))
				if err == nil {
					// This is a temporary workaround to ensure all S3 streams are readable.
					// The proper solution for this require an SQS message tracker that allows true concurrent processing.
					// The overall behavior of the system does not change since reading was triggered
					// when we were detecting MIME types by using `Peek()`.
					err = kickOffReaders(ctx, dataStreams)
				}
				if err != nil {
					// No need for error here. This issue can happen due to
					// 1. Persistent AWS issues while accessing S3 object
					// 2. Misconfiguration from user side (e.g. not configured IAM role permissions properly
					// In both cases no need to log an error - the message will reappear in the queue after the Visibility Timeout has expired
					// If the message fails repeatedly, it will end up in the DLQ and an alarm will fire
					zap.L().Warn("Skipping event due to error", zap.Error(err))
					continue
				}

				for _, s := range dataStreams {
					select {
					case streamChan <- s:
					case <-ctx.Done():
						return
					}
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

	// delete messages from sqs q on success (best effort)
	sqsbatch.DeleteMessageBatch(sqsClient, common.Config.SqsQueueURL, accumulatedMessageReceipts)
	return len(accumulatedMessageReceipts), nil
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
	input := &sqs.ReceiveMessageInput{
		WaitTimeSeconds:     aws.Int64(0),
		MaxNumberOfMessages: aws.Int64(common.Config.SqsBatchSize),
		QueueUrl:            &common.Config.SqsQueueURL,
	}
	output, err := sqsClient.ReceiveMessageWithContext(ctx, input)

	if err != nil && !awsutils.IsAnyError(err, request.CanceledErrorCode) {
		err = errors.Wrapf(err, "failure receiving messages from %s", common.Config.SqsQueueURL)
		return nil, err
	}

	return output.Messages, nil
}

func kickOffReaders(ctx context.Context, streams []*common.DataStream) error {
	grp, _ := errgroup.WithContext(ctx)
	for _, s := range streams {
		s := s
		r, ok := s.Closer.(io.ReadCloser)
		if !ok {
			continue
		}
		grp.Go(func() error {
			err := readZero(r)
			logmetrics.GetObject.With(
				metrics.SourceIDDimension, s.Source.IntegrationID,
				metrics.StatusDimension, statusFromErr(err),
			).Add(1)
			return err
		})
	}
	return grp.Wait()
}

func readZero(r io.Reader) error {
	buf := [0]byte{}
	_, err := r.Read(buf[:])
	return err
}

// Returns the correct Status dimension from the provided error
func statusFromErr(err error) string {
	if err == nil {
		return logmetrics.StatusOK
	}
	if awsutils.IsAnyError(err, "AccessDenied") {
		return logmetrics.StatusAuthErr
	}
	return logmetrics.StatusErr
}
