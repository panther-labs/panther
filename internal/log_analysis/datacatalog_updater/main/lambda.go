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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/awsglue"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

const (
	maxRetries = 20 // setting Max Retries to a higher number - we'd like to retry VERY hard before failing.
)

var (
	validation                   = validator.New()
	glueClient glueiface.GlueAPI = glue.New(session.Must(session.NewSession(aws.NewConfig().WithMaxRetries(maxRetries))))
	// partitionPrefixCache is a cache that stores all the prefixes of the partitions we have created
	// The cache is used to avoid attempts to create the same partitions in Glue table
	partitionPrefixCache = make(map[string]struct{})
)

func main() {
	lambda.Start(handle)
}

func handle(ctx context.Context, event events.SQSEvent) (err error) {
	lc, _ := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := common.OpLogManager.Start(lc.InvokedFunctionArn, common.OpLogLambdaServiceDim).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err, zap.Int("sqsMessageCount", len(event.Records)))
	}()
	err = process(event)
	return err
}

func process(event events.SQSEvent) error {
	for _, record := range event.Records {
		zap.L().Debug("processing record", zap.String("content", record.Body))
		notification := &models.S3Notification{}
		if err := jsoniter.UnmarshalFromString(record.Body, notification); err != nil {
			zap.L().Error("failed to unmarshal record", zap.Error(errors.WithStack(err)))
			continue
		}

		if err := validation.Struct(notification); err != nil {
			zap.L().Error("received invalid message", zap.Error(errors.WithStack(err)))
			continue
		}

		gluePartition, err := awsglue.GetPartitionFromS3(*notification.S3Bucket, *notification.S3ObjectKey)
		if err != nil {
			zap.L().Error("failed to get partition information from notification",
				zap.Any("notification", notification), zap.Error(errors.WithStack(err)))
			continue
		}

		// already done?
		partitionLocation := gluePartition.GetPartitionLocation()
		if _, ok := partitionPrefixCache[partitionLocation]; ok {
			zap.L().Debug("partition has already been created")
			continue
		}

		err = gluePartition.CreatePartition(glueClient)
		if err != nil {
			err = errors.Wrapf(err, "failed to create partition: %#v", notification)
			return err
		}
		partitionPrefixCache[partitionLocation] = struct{}{} // remember
	}
	return nil
}
