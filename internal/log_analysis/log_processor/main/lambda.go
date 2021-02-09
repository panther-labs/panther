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
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/compliance/snapshotlogs"
	"github.com/panther-labs/panther/internal/core/logtypesapi"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/metrics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/processor"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

const (
	// How often we check if we need to scale (controls responsiveness).
	defaultScalingDecisionInterval = 30 * time.Second
)

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

	apiResolver := &logtypesapi.Resolver{
		LogTypesAPI: &logtypesapi.LogTypesAPILambdaClient{
			LambdaName: logtypesapi.LambdaName,
			LambdaAPI:  common.LambdaClient,
			Validate:   validator.New().Struct,
		},
		NativeLogTypes: logtypes.MustMerge("native", registry.NativeLogTypes(), snapshotlogs.LogTypes()),
	}

	// We also need the cloud-security resolvers to handle their delivered S3 objects
	resolver := logtypes.ChainResolvers(apiResolver, snapshotlogs.Resolver())

	// Log cases where a log type failed to resolve. Almost certainly something is amiss in the DDB.
	logTypesResolver := logtypes.ResolverFunc(func(ctx context.Context, name string) (logtypes.Entry, error) {
		entry, err := resolver.Resolve(ctx, name)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			// if a logType is not found, this indicates bad data ... log/alarm
			lambdalogger.FromContext(ctx).Error("cannot resolve log type", zap.String("logType", name))
			return nil, nil
		}
		return entry, nil
	})

	// Configure metrics
	cwCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Sync metrics every minute
	go metrics.CWManager.Run(cwCtx, time.Minute)
	defer func() {
		// Force syncing metrics at the end of the invocation
		if err := metrics.CWManager.Sync(); err != nil {
			zap.L().Warn("failed to sync metrics", zap.Error(err))
		}
	}()

	parsersResolver := logtypes.ParserResolver(logTypesResolver)
	sqsMessageCount, err = processor.PollEvents(ctx, common.SqsClient, parsersResolver)

	return err
}
