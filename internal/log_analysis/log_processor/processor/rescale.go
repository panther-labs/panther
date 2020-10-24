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
	"time"

	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/box"
)

const (
	// How often we check if we need to scale (controls responsiveness).
	defaultProcessingScaleDecisionInterval = time.Second * 30

	// This limits how many lambdas can be invoked at once to cap rate of scaling (controls responsiveness).
	// Setting this higher leads to faster response to spikes but risks throttling very quickly.
	// Since each lambda makes this decision locally, this results in an exponential response under load.
	// For example, if there is a load spike of a million events, then the first lambda will spawn
	// a few new lambdas, they will work on the load but not drain the queue, then THEY spawn more lambdas,
	// and this continues until the load reduces.
	processingMaxLambdaInvoke = 1
)

var (
	processingScaleDecisionInterval = defaultProcessingScaleDecisionInterval // var so we can set in tests
)

// scalingDecisions makes adaptive (now we can say we do ML!) decisions to scale up based on the sqs queue stats periodically
func scalingDecisions(sqsClient sqsiface.SQSAPI, lambdaClient lambdaiface.LambdaAPI) chan bool {
	stopScaling := make(chan bool)

	go func() {
		ticker := time.NewTicker(processingScaleDecisionInterval)
		defer ticker.Stop()
		poll := true
		for poll {
			select {
			case <-ticker.C:
			case <-stopScaling:
				poll = false
			}

			// check if we need to scale
			totalQueuedMessages, err := queueDepth(sqsClient) // this includes queued and delayed messages
			if err != nil {
				zap.L().Warn("rescale cannot read from sqs queue", zap.Error(err))
				continue
			}

			// the number of lambdas to invoke are proportional to the message count (clipped to processingMaxLambdaInvoke)
			processingScaleUp(lambdaClient, totalQueuedMessages/processingMaxFilesLimit)
		}
	}()

	return stopScaling
}

// processingScaleUp will execute nLambdas to take on more load
func processingScaleUp(lambdaClient lambdaiface.LambdaAPI, nLambdas int) {
	if nLambdas > 0 {
		if nLambdas > processingMaxLambdaInvoke { // clip to cap rate of increase under very high load
			nLambdas = processingMaxLambdaInvoke
		}
		zap.L().Debug("scaling up", zap.Int("nLambdas", nLambdas))
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
