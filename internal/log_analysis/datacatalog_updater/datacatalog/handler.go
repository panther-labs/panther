package datacatalog

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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

type LambdaHandler struct {
	CompactorQueueURL     string
	ProcessedDataBucket   string
	AthenaWorkgroup       string
	QueueURL              string
	ListAvailableLogTypes func(ctx context.Context) ([]string, error)
	GlueClient            glueiface.GlueAPI
	LambdaClient          lambdaiface.LambdaAPI
	Resolver              logtypes.Resolver
	AthenaClient          athenaiface.AthenaAPI
	SQSClient             sqsiface.SQSAPI
	Logger                *zap.Logger

	// S3 Partition URLs for each request
	batchS3Partitions []string
	// Glue partitions known to have been created. (use map[string]string where key == value for map size)
	partitionsCreated map[string]string
}

var _ lambda.Handler = (*LambdaHandler)(nil)

type sqsTask struct {
	Records                []events.S3EventRecord
	SyncDatabase           *SyncDatabaseEvent
	CreateTables           *CreateTablesEvent
	SyncDatabasePartitions *SyncDatabasePartitionsEvent
	SyncTablePartitions    *SyncTableEvent
}

func (h *LambdaHandler) Invoke(ctx context.Context, payload []byte) ([]byte, error) {
	ctx = lambdalogger.Context(ctx, h.Logger)
	event := events.SQSEvent{}
	if err := jsoniter.Unmarshal(payload, &event); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal JSON payload")
	}
	if err := h.HandleSQSEvent(ctx, &event); err != nil {
		return nil, err
	}
	return []byte(`{"status":"OK"}`), nil
}

func (h *LambdaHandler) HandleSQSEvent(ctx context.Context, event *events.SQSEvent) error {
	tasks, err := tasksFromSQSMessages(event.Records...)
	if err != nil {
		return err
	}
	for _, task := range tasks {
		switch task := task.(type) {
		case *events.S3Event:
			err = h.HandleS3Event(ctx, task)
		case *CreateTablesEvent:
			err = h.HandleCreateTablesEvent(ctx, task)
		case *SyncDatabaseEvent:
			err = h.HandleSyncDatabaseEvent(ctx, task)
		case *SyncDatabasePartitionsEvent:
			err = h.HandleSyncDatabasePartitionsEvent(ctx, task)
		case *SyncTableEvent:
			err = h.HandleSyncTableEvent(ctx, task)
		default:
			err = errors.New("invalid task")
		}
	}
	if err != nil {
		return err
	}
	return nil
}

func tasksFromSQSMessages(messages ...events.SQSMessage) (tasks []interface{}, err error) {
	var s3Events []events.S3EventRecord
	for _, msg := range messages {
		task := sqsTask{}
		if e := jsoniter.UnmarshalFromString(msg.Body, &task); e != nil {
			err = multierr.Append(err, errors.WithMessagef(err, "invalid JSON payload for SQS message %q", msg.MessageId))
			continue
		}
		switch {
		case task.Records != nil:
			s3Events = append(s3Events, task.Records...)
		case task.SyncDatabase != nil:
			tasks = append(tasks, task.SyncDatabase)
		case task.SyncDatabasePartitions != nil:
			tasks = append(tasks, task.SyncDatabasePartitions)
		case task.SyncTablePartitions != nil:
			tasks = append(tasks, task.SyncTablePartitions)
		case task.CreateTables != nil:
			tasks = append(tasks, task.CreateTables)
		default:
			err = multierr.Append(err, errors.Errorf("invalid SQS message body %q", msg.MessageId))
		}
	}
	if len(s3Events) > 0 {
		tasks = append(tasks, &events.S3Event{
			Records: s3Events,
		})
	}
	return
}
