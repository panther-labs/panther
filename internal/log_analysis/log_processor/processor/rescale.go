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
	"math"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/awsutils"
	"github.com/panther-labs/panther/pkg/box"
)

const (
	// This limits how many lambdas can be invoked at once to cap rate of scaling (controls responsiveness).
	// Setting this higher leads to faster response to spikes but risks throttling very quickly.
	// Since each lambda makes this decision locally, this results in an exponential response under load.
	// For example, if there is a load spike of a million events, then the first lambda will spawn
	// a few new lambdas, they will work on the load but not drain the queue, then THEY spawn more lambdas,
	// and this continues to expand until the load reduces.
	processingMaxLambdaInvoke = 2

	// The message increase required to trigger a rescale
	processingQueueIncreaseThreshold = 5

	// The fraction of backlog file to execute lambdas against
	processingLambdaPercentInvoke = 0.1
)

// RunScalingDecisions makes periodic adaptive decisions to scale up based on the sqs queue stats
func RunScalingDecisions(ctx context.Context, sqsClient sqsiface.SQSAPI, lambdaClient lambdaiface.LambdaAPI, interval time.Duration) {
	lastTotalQueueMessages := math.MaxInt32
	ticker := time.NewTicker(interval)

	// check if we need to scale
	scalingDecisions := func() {
		totalQueuedMessages, err := queueDepth(ctx, sqsClient)
		if err != nil {
			zap.L().Warn("rescale cannot read from sqs queue", zap.Error(err))
			return
		}

		nMoreLambdas := 0

		// for increasing queue size (positive gradient): the threshold is used to avoid over reacting to small changes
		if totalQueuedMessages-lastTotalQueueMessages > processingQueueIncreaseThreshold {
			nMoreLambdas++
		}
		lastTotalQueueMessages = totalQueuedMessages

		// for the backlog (dc offset):
		if lastTotalQueueMessages > processingQueueIncreaseThreshold {
			nMoreLambdas += int(float32(lastTotalQueueMessages) * processingLambdaPercentInvoke)
		}

		processingScaleUp(ctx, lambdaClient, nMoreLambdas)
	}

	defer scalingDecisions() // always run at end of cycle

	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
		scalingDecisions()
	}
}

// queueDepth returns the QueueAttributeNameApproximateNumberOfMessages
func queueDepth(ctx context.Context, sqsClient sqsiface.SQSAPI) (int, error) {
	getQueueAttributesInput := &sqs.GetQueueAttributesInput{
		AttributeNames: []*string{
			aws.String(sqs.QueueAttributeNameApproximateNumberOfMessages), // tells us there is waiting events now
		},
		QueueUrl: &common.Config.SqsQueueURL,
	}
	getQueueAttributesOutput, err := sqsClient.GetQueueAttributesWithContext(ctx, getQueueAttributesInput)
	if err != nil && !awsutils.IsAnyError(err, request.CanceledErrorCode) {
		err = errors.Wrapf(err, "failure getting message count from %s", common.Config.SqsQueueURL)
		return 0, err
	}
	// number of messages
	numberOfQueuedMessages, err := getQueueIntegerAttribute(getQueueAttributesOutput.Attributes,
		sqs.QueueAttributeNameApproximateNumberOfMessages)
	if err != nil {
		return 0, err
	}

	return numberOfQueuedMessages, err
}

func getQueueIntegerAttribute(attrs map[string]*string, attr string) (count int, err error) {
	intAsStringPtr := attrs[attr]
	if intAsStringPtr == nil { // assume 0
		return 0, nil
	}
	count, err = strconv.Atoi(*intAsStringPtr)
	if err != nil {
		err = errors.Wrapf(err, "failure reading %s (%s) count from %s", attr, *intAsStringPtr, common.Config.SqsQueueURL)
		return 0, err
	}
	return count, err
}

// processingScaleUp will execute nLambdas to take on more load
func processingScaleUp(ctx context.Context, lambdaClient lambdaiface.LambdaAPI, nLambdas int) {
	if nLambdas <= 0 {
		return
	}
	if nLambdas > processingMaxLambdaInvoke { // clip to cap rate of increase under very high load
		nLambdas = processingMaxLambdaInvoke
	}
	zap.L().Debug("scaling up", zap.Int("nLambdas", nLambdas))
	for i := 0; i < nLambdas; i++ {
		resp, err := lambdaClient.InvokeWithContext(ctx, &lambda.InvokeInput{
			FunctionName:   box.String("panther-log-processor"),
			Payload:        []byte(`{"tick": true}`),
			InvocationType: box.String(lambda.InvocationTypeEvent), // don't wait for response
		})
		if err != nil && !awsutils.IsAnyError(err, request.CanceledErrorCode) {
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
