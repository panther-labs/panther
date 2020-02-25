package main

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/processor"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"gopkg.in/go-playground/validator.v9"
)

var validation =  validator.New()

func main() {
	lambda.Start(handle)
}

func handle(ctx context.Context, event events.SQSEvent) error {
	lc, _ := lambdalogger.ConfigureGlobal(ctx, nil)
	return process(lc, event)
}

func process(lc *lambdacontext.LambdaContext, event events.SQSEvent) (err error) {
	operation := common.OpLogManager.Start(lc.InvokedFunctionArn, common.OpLogLambdaServiceDim).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err, zap.Int("sqsMessageCount", len(event.Records)))
	}()

	for _, record := range event.Records {
		notification := &models.S3Notification{}
		if err :=  jsoniter.UnmarshalFromString(record.Body, notification); err != nil {
			zap.L().Error("failed to unmarshal record", zap.Error(errors.WithStack(err)))
			continue
		}

		if err := validation.Struct(notification); err != nil {
			zap.L().Error("received invalid message", zap.Error(errors.WithStack(err)))
			continue
		}

		gluePartition := notification.S3ObjectKey

	}

}
