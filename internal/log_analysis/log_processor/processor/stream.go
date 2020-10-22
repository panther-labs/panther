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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
	"github.com/panther-labs/panther/pkg/box"
)

const (
	// How often we check if we need to scale (controls responsiveness).
	processingScaleDecisionInterval = time.Minute

	// The min threshold to trigger scaling based on gradient estimate of sqs q (messages % change / sec).
	processingMinGradientThreshold = 0.05

	// This limits how many lambdas can be invoked at once to cap rate of scaling (controls responsiveness).
	processingMaxLambdaInvoke = 1

	// Limit this so there is time to delete from the queue at the end.
	processingMaxFilesLimit = 5000

	// The processing runtime should be shorter than lambda timeout to make room to flush buffers ad the end of the cycle.
	processingTimeLimitDivisor = 2

	// The max messages per read for SQS (can't find an sqs constant to refer to).
	sqsMaxBatchSize = 10
)

/*
StreamEvents acts as an interface to aggregate sqs messages to avoid many small S3 files being created under load.
The function will attempt to read more messages from the queue when the queue has messages. Under load
the lambda will continue to read events and maximally aggregate data to produce fewer, bigger files.
Fewer, bigger files makes Athena queries much faster.
*/
func StreamEvents(
	sqsClient sqsiface.SQSAPI,
	lambdaClient lambdaiface.LambdaAPI,
	resolver logtypes.Resolver,
	deadlineTime time.Time,
) (sqsMessageCount int, err error) {

	newProcessor := NewFactory(resolver)
	process := func(streams <-chan *common.DataStream, dest destinations.Destination) error {
		return Process(streams, dest, newProcessor)
	}
	return streamEvents(sqsClient, lambdaClient, deadlineTime, process, sources.ReadSnsMessages)
}

// entry point for unit testing, pass in read/process functions
func streamEvents(
	sqsClient sqsiface.SQSAPI,
	lambdaClient lambdaiface.LambdaAPI,
	deadlineTime time.Time,
	processFunc ProcessFunc,
	generateDataStreamsFunc func([]string) ([]*common.DataStream, error)) (int, error) {

	// this cannot be a named return var because it would cause a data race
	var sqsMessageCount int

	streamChan := make(chan *common.DataStream, 2*sqsMaxBatchSize) // use small buffer to pipeline events
	processingDeadlineTime := processingDeadlineTime(deadlineTime)

	var accumulatedMessageReceipts []*string // accumulate message receipts for delete at the end

	readEventErrorChan := make(chan error, 1) // below go routine closes over this for errors, 1 deep buffer
	go func() {
		// runs periodically during processing making scaling decisions
		stopScaling := scalingDecisions(sqsClient, lambdaClient)

		defer func() {
			stopScaling <- true       // terminate the scaling go routine
			close(streamChan)         // done reading messages, this will cause processFunc() to return
			close(readEventErrorChan) // no more writes on err chan
		}()

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

			// under no load we do not read from the sqs queue and just exit
			totalQueuedMessages, err := queueDepth(sqsClient) // this includes queued and delayed messages
			if err != nil {
				readEventErrorChan <- err
				return
			}
			if totalQueuedMessages == 0 {
				break
			}

			// keep reading from SQS to maximize output aggregation
			messages, messageReceipts, err := sqsbatch.ReceiveMessage(sqsClient,
				common.Config.SqsQueueURL, common.SQSWaitTimeSec)
			if err != nil {
				readEventErrorChan <- err
				return
			}

			if len(messages) == 0 { // no work to do but maybe more later OR reached the max sqs messages allowed in flight, either way need to break
				break
			}

			// remember so we can delete when done
			accumulatedMessageReceipts = append(accumulatedMessageReceipts, messageReceipts...)

			// extract from sqs read responses
			dataStreams, err := sqsDataStreams(messages, generateDataStreamsFunc)
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
	return sqsMessageCount, nil
}

// processingDeadlineTime calcs a time less than the deadllineTime to allow time for buffers to flush
func processingDeadlineTime(deadlineTime time.Time) time.Time {
	// NOTE: time.Since(deadlineTime) will be negative since the deadline is in the future!
	return deadlineTime.Add(time.Since(deadlineTime) / processingTimeLimitDivisor)
}

// scalingDecisions makes decisions to scale up based on the sqs queue stats periodically
func scalingDecisions(sqsClient sqsiface.SQSAPI, lambdaClient lambdaiface.LambdaAPI) chan bool {
	stopScaling := make(chan bool)

	var initialTotalQueuedMessages int // first non-zero estimate of queue size
	var lastTotalQueuedMessages int    // last non-zero estimate of queue size

	startProcessingTime := time.Now()
	go func() {
		loop := true
		for loop {
			select {
			// check if we need to scale
			case <-time.After(processingScaleDecisionInterval):
			case <-stopScaling:
				loop = false
			}

			totalQueuedMessages, err := queueDepth(sqsClient) // this includes queued and delayed messages
			if err != nil {
				continue
			}
			// use these to estimate the derivative of the load on the events q (I said `derivative`, this must be ML!)
			if initialTotalQueuedMessages == 0 { // first non-zero estimate
				initialTotalQueuedMessages = totalQueuedMessages
			}
			// last non-zero estimate
			lastTotalQueuedMessages = totalQueuedMessages

			scalingDecision(lambdaClient, initialTotalQueuedMessages, lastTotalQueuedMessages,
				time.Since(startProcessingTime).Seconds())
		}
	}()

	return stopScaling
}

// scalingDecision makes a decision to scale up based on the sqs queue stats
func scalingDecision(lambdaClient lambdaiface.LambdaAPI,
        initialTotalQueuedMessages, lastTotalQueuedMessages int, secondsSinceStart float64) {

	// if the slope of the change in event q is enough, then rescale relative to the change (gradient ascent)
	gradient, gradientGood := queueGradient(initialTotalQueuedMessages, lastTotalQueuedMessages, secondsSinceStart)
	if gradientGood { // only if there was enough data to calculate a gradient
		if gradient >= processingMinGradientThreshold {
			processingScaleUp(lambdaClient, (lastTotalQueuedMessages-initialTotalQueuedMessages)/processingMaxFilesLimit)
		}
		// if the gradient is above -processingMinGradientThreshold, then work to reduce the dc bias in the event q curve
		// NOTE: we do not do this if the gradient is RAPIDLY decreasing to avoid over shooting
		if gradient > -processingMinGradientThreshold {
			processingScaleUp(lambdaClient, lastTotalQueuedMessages/processingMaxFilesLimit)
		}
	}
}

// queueGradient returns estimate of change to number of events in sqs queue and a boolean to indicate success
func queueGradient(initialTotalQueuedMessages, lastTotalQueuedMessages int, secondsSinceStart float64) (float64, bool) {
	if secondsSinceStart < 30 { // not enough time to get good estimate
		return 0.0, false
	}
	if lastTotalQueuedMessages < processingMaxFilesLimit { // not enough messages to get good estimate
		return 0.0, false
	}
	changeRatio := float64(lastTotalQueuedMessages-initialTotalQueuedMessages) / float64(lastTotalQueuedMessages)
	return changeRatio / secondsSinceStart, true
}

// processingScaleUp will execute nLambdas to take on more load
func processingScaleUp(lambdaClient lambdaiface.LambdaAPI, nLambdas int) {
	if nLambdas > 0 {
		if nLambdas > processingMaxLambdaInvoke { // clip to cap rate of increase under very high load
			nLambdas = processingMaxLambdaInvoke
		}
		zap.L().Info("scaling up", zap.Int("nLambdas", nLambdas))
		for i := 0; i < nLambdas; i++ {
			resp, err := lambdaClient.Invoke(&lambda.InvokeInput{
				FunctionName:   box.String("panther-log-processor"),
				Payload:        []byte(`{"tick": true}`),
				InvocationType: box.String(lambda.InvocationTypeEvent), // don't wait for response
			})
			if err != nil {
				zap.L().Error("scaling up failed to invoke log processor",
					zap.Error(errors.WithStack(err)))
				return
			}
			if resp.FunctionError != nil {
				zap.L().Error("scaling up failed to invoke log processor",
					zap.Error(errors.Errorf(*resp.FunctionError)))
				return
			}
		}
	}
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

func queueDepth(sqsClient sqsiface.SQSAPI) (totalQueuedMessages int, err error) {
	getQueueAttributesInput := &sqs.GetQueueAttributesInput{
		AttributeNames: []*string{
			aws.String(sqs.QueueAttributeNameApproximateNumberOfMessages),        // tells us there is waiting events now
			aws.String(sqs.QueueAttributeNameApproximateNumberOfMessagesDelayed), // tells us that there will be events in the near future
		},
		QueueUrl: &common.Config.SqsQueueURL,
	}
	getQueueAttributesOutput, err := sqsClient.GetQueueAttributes(getQueueAttributesInput)
	if err != nil {
		err = errors.Wrapf(err, "failure getting message count from %s", common.Config.SqsQueueURL)
		return 0, err
	}
	// number of messages
	numberOfQueuedMessages, err := getQueueIntegerAttribute(getQueueAttributesOutput.Attributes,
		sqs.QueueAttributeNameApproximateNumberOfMessages)
	if err != nil {
		return 0, err
	}
	// number of delayed messages, the q should be set up with a delay so we can "see" if there are more events
	numberOfQueuedMessagesDelayed, err := getQueueIntegerAttribute(getQueueAttributesOutput.Attributes,
		sqs.QueueAttributeNameApproximateNumberOfMessagesDelayed)
	if err != nil {
		return 0, err
	}
	return numberOfQueuedMessages + numberOfQueuedMessagesDelayed, err
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
