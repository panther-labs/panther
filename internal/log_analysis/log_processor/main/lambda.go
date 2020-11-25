package main

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
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/processor"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

// How often we check if we need to scale (controls responsiveness).
const defaultScalingDecisionInterval = 30 * time.Second

func main() {
	common.Setup()
	lambda.Start(handle)
}

func handle(ctx context.Context) error {
	lambdalogger.ConfigureGlobal(ctx, nil)
	return process(ctx, defaultScalingDecisionInterval)
}

func process(ctx context.Context, scalingDecisionInterval time.Duration) (err error) {
	lc, _ := lambdacontext.FromContext(ctx)
	operation := common.OpLogManager.Start(lc.InvokedFunctionArn, common.OpLogLambdaServiceDim).WithMemUsed(lambdacontext.MemoryLimitInMB)

	// Create cancellable deadline for Scaling Decisions go routine
	scalingCtx, cancelScaling := context.WithCancel(ctx)
	// runs in the background, periodically polling the queue to make scaling decisions
	go processor.RunScalingDecisions(scalingCtx, common.SqsClient, common.LambdaClient, scalingDecisionInterval)

	var sqsMessageCount int
	defer func() {
		cancelScaling()
		operation.Stop().Log(err, zap.Int("sqsMessageCount", sqsMessageCount))
	}()

	logTypesResolver := registry.NativeLogTypesResolver()

	sqsMessageCount, err = processor.PollEvents(ctx, common.SqsClient, logTypesResolver)

	return err
}
