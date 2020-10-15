package process

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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

func Handle(ctx context.Context, event *DataCatalogEvent) (err error) {
	lc, logger := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := common.OpLogManager.Start(lc.InvokedFunctionArn, common.OpLogLambdaServiceDim).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err,
			zap.Int("sqsMessageCount", len(event.Records)))
	}()

	// This lambda handles 3 type of events:
	switch {
	// 1. A SyncDatabase event to trigger a full database sync (used by custom resource manager)
	case event.SyncDatabaseEvent != nil:
		ctx = lambdalogger.Context(ctx, logger)
		err = HandleSyncEvent(ctx, event.SyncDatabaseEvent)
	// 2. A SyncTablePartitions event to trigger a single table sync (triggered recursively by sync database events)
	case event.SyncTablePartitions != nil:
		ctx = lambdalogger.Context(ctx, logger)
		err = HandleSyncTableEvent(ctx, event.SyncTablePartitions)
	// 3. An SQS message. See handleSQSEvent() for the supported message types.
	default:
		err = handleSQSEvent(event.SQSEvent)
	}
	return
}

func handleSQSEvent(event events.SQSEvent) error {
	for _, record := range event.Records {
		// uncomment to see all payloads
		//zap.L().Debug("processing record", zap.String("content", record.Body))
		if msgType, ok := record.MessageAttributes[PantherMessageType]; ok &&
			aws.StringValue(msgType.StringValue) == aws.StringValue(CreateTableMessageAttribute.StringValue) {

			msg := CreateTablesMessage{}
			if err := jsoniter.UnmarshalFromString(record.Body, &msg); err != nil {
				err = errors.WithStack(err)
				zap.L().Error("failed to unmarshal record", zap.Error(err))
				continue
			}
			err := HandleCreateTablesMessage(context.TODO(), &msg)
			if err != nil {
				return err
			}
		} else {
			notification := S3Notification{}
			if err := jsoniter.UnmarshalFromString(record.Body, &notification); err != nil {
				zap.L().Error("failed to unmarshal record", zap.Error(errors.WithStack(err)))
				continue
			}
			err := HandleS3Notification(notification)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
