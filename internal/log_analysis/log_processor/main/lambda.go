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

func main() {
	common.Setup()
	lambda.Start(handle)
}

func handle(ctx context.Context) error {
	lambdalogger.ConfigureGlobal(ctx, nil)
	return process(ctx)
}

func process(ctx context.Context) (err error) {
	lc, _ := lambdacontext.FromContext(ctx)
	operation := common.OpLogManager.Start(lc.InvokedFunctionArn, common.OpLogLambdaServiceDim).WithMemUsed(lambdacontext.MemoryLimitInMB)

	cancelScaling := scheduleScalingDecisions(ctx)
	var sqsMessageCount int
	defer func() {
		cancelScaling()
		operation.Stop().Log(err, zap.Int("sqsMessageCount", sqsMessageCount))
	}()

	logTypesResolver := registry.NativeLogTypesResolver()
	deadline, _ := ctx.Deadline() // TODO Remove deadline, rely on ctx for cancellation
	sqsMessageCount, err = processor.StreamEvents(ctx, common.SqsClient, logTypesResolver, deadline)

	return err
}

func scheduleScalingDecisions(ctx context.Context) context.CancelFunc {
	// Create cancellable deadline for Scaling Decisions go routine
	ctx, cancel := context.WithCancel(ctx)
	// runs periodically during processing making scaling decisions
	// How often we check if we need to scale (controls responsiveness).
	const scalingDecisionInterval = 30 * time.Second
	processor.ScalingDecisions(ctx, common.SqsClient, common.LambdaClient, scalingDecisionInterval)
	return cancel
}
