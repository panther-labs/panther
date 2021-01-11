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

import (
	"context"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/oplog"
)

type LambdaHandler struct {
	ProcessedDataBucket   string
	AthenaWorkgroup       string
	QueueURL              string
	ListAvailableLogTypes func(ctx context.Context) ([]string, error)
	GlueClient            glueiface.GlueAPI
	Resolver              logtypes.Resolver
	AthenaClient          athenaiface.AthenaAPI
	SQSClient             sqsiface.SQSAPI
	Logger                *zap.Logger

	// Glue partitions known to have been created.
	partitionsCreated map[string]struct{}
}

var _ lambda.Handler = (*LambdaHandler)(nil)

type sqsTask struct {
	Records                []events.S3EventRecord       `json:",omitempty"`
	SyncDatabase           *SyncDatabaseEvent           `json:",omitempty"`
	CreateTables           *CreateTablesEvent           `json:",omitempty"`
	SyncDatabasePartitions *SyncDatabasePartitionsEvent `json:",omitempty"`
	SyncTablePartitions    *SyncTableEvent              `json:",omitempty"`
	UpdateTable            *UpdateTablesEvent           `json:",omitempty"`
}

// Invoke implements lambda.Handler interface.
//
// This is the main entry point for Lambda code.
func (h *LambdaHandler) Invoke(ctx context.Context, payload []byte) ([]byte, error) {
	ctx = lambdalogger.Context(ctx, h.Logger)
	event := events.SQSEvent{}
	if err := jsoniter.Unmarshal(payload, &event); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal Lambda payload")
	}
	if err := h.HandleSQSEvent(ctx, &event); err != nil {
		return nil, err
	}
	return nil, nil
}

var opLogManager = oplog.NewManager("log_analysis", "datacatalog_updater")

// HandleSQSEvent handles messages in an SQS event.
func (h *LambdaHandler) HandleSQSEvent(ctx context.Context, event *events.SQSEvent) (err error) {
	// NOTE: this logging is needed for alarming and dashboards!
	lc, _ := lambdacontext.FromContext(ctx)
	operation := opLogManager.Start(lc.InvokedFunctionArn).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err)
	}()

	var tasks []interface{}
	tasks, err = tasksFromSQSMessages(event.Records...)
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
		case *UpdateTablesEvent:
			err = h.HandleUpdateTablesEvent(ctx, task)
		default:
			err = errors.New("invalid task")
		}
		// We fail immediately on first failed task so that all messages are retried later.
		// The tasksFromSQSMessages function makes sure S3 events are processed first.
		if err != nil {
			return err
		}
	}
	return nil
}

// tasksFromSQSMessages parses SQS messages and organizes them into distinct tasks.
//
// A single SQS event can contain multiple messages and each message can contain multiple S3Record events.
// This function will aggregate all S3Record events into a single S3Event so that they are all handled together.
// It also ensures that S3 events are processed before sync-related events.
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
			// Aggregate all events.S3EventRecord values together
			s3Events = append(s3Events, task.Records...)
		case task.SyncDatabase != nil:
			tasks = append(tasks, task.SyncDatabase)
		case task.SyncDatabasePartitions != nil:
			tasks = append(tasks, task.SyncDatabasePartitions)
		case task.SyncTablePartitions != nil:
			tasks = append(tasks, task.SyncTablePartitions)
		case task.CreateTables != nil:
			tasks = append(tasks, task.CreateTables)
		case task.UpdateTable != nil:
			tasks = append(tasks, task.UpdateTable)
		default:
			err = multierr.Append(err, errors.Errorf("invalid SQS message body %q", msg.MessageId))
		}
	}
	// If any event.S3EventRecord values where collected, add them as a single events.S3Event task
	if len(s3Events) > 0 {
		// It is important to process the S3 events first.
		// This ensures that sync and update events (which can queue up more events) are not retried due to errors in
		// the 'simple' S3 events.
		tasks = append([]interface{}{
			&events.S3Event{
				Records: s3Events,
			},
		}, tasks...)
	}
	return tasks, err
}
