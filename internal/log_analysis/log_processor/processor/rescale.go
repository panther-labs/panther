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
	processingScaleDecisionInterval = time.Second * 30

	// This limits how many lambdas can be invoked at once to cap rate of scaling (controls responsiveness).
	processingMaxLambdaInvoke = 1

	// Limit this so there is time to delete from the queue at the end.
	processingMaxFilesLimit = 5000
)

// scalingDecisions makes decisions to scale up based on the sqs queue stats periodically
func scalingDecisions(sqsClient sqsiface.SQSAPI, lambdaClient lambdaiface.LambdaAPI) chan bool {
	stopScaling := make(chan bool)

	go func() {
		poll := true
		for poll {
			select {
			// check if we need to scale
			case <-time.After(processingScaleDecisionInterval):
			case <-stopScaling:
				poll = false
			}

			totalQueuedMessages, err := queueDepth(sqsClient) // this includes queued and delayed messages
			if err != nil {
				zap.L().Warn("recale cannot read from sqs queue", zap.Error(err))
				continue
			}

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
