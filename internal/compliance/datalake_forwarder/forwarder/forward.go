package forwarder

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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/aws/aws-sdk-go/service/firehose/firehoseiface"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/forwarder/events"
	"github.com/panther-labs/panther/pkg/awsbatch/firehosebatch"
)

const (
	ChangeTypeCreate = "CREATED"
	ChangeTypeDelete = "DELETED"
	ChangeTypeModify = "MODIFIED"
	ChangeTypeSync   = "SYNC"
	recordDelimiter  = '\n'
	maxRetries       = 10
)

type StreamHandler struct {
	FirehoseClient     firehoseiface.FirehoseAPI
	LambdaClient       lambdaiface.LambdaAPI
	StreamName         string
	integrationIDCache map[string]string
	lastUpdatedCache   time.Time
}

// Run is the entry point for the datalake-forwarder lambda
func (sh *StreamHandler) Run(ctx context.Context, logger *zap.Logger, event *events.DynamoDBEvent) (err error) {
	firehoseRecords := make([]*firehose.Record, 0, len(event.Records))
	for i := range event.Records {
		// We should be passing pointers to avoid copy of the record struct
		record := &event.Records[i]
		changes, ok, err := sh.getChanges(record)
		if err != nil {
			logger.Error("failed to process record",
				zap.Error(err),
				zap.String("eventID", record.EventID),
				zap.String("eventName", record.EventName),
				zap.String("eventSourceARN", record.EventSourceArn),
			)
			continue
		}
		if !ok {
			logger.Warn("Skipping record",
				zap.Error(err),
				zap.String("eventID", record.EventID),
				zap.String("eventName", record.EventName),
				zap.String("eventSourceARN", record.EventSourceArn),
			)
			continue
		}
		data, err := jsoniter.Marshal(changes)
		if err != nil {
			logger.Error("failed to get marshal changes to JSON", zap.Error(err), zap.String("eventId", record.EventID))
			continue
		}

		data = append(data, recordDelimiter)
		firehoseRecords = append(firehoseRecords, &firehose.Record{Data: data})
	}

	if len(firehoseRecords) == 0 {
		logger.Debug("no records to process")
		return nil
	}
	// Maximum Kinesis Firehose batch put request is 4MB, but we may be processing much more than
	// that so we have to send in batches
	firehoseInput := firehose.PutRecordBatchInput{
		Records:            firehoseRecords,
		DeliveryStreamName: &sh.StreamName,
	}
	bigMessages, err := firehosebatch.BatchSend(ctx, sh.FirehoseClient, firehoseInput, maxRetries)
	if len(bigMessages) > 0 {
		logger.Error("unable to send some records as they are too large", zap.Int("numRecords", len(bigMessages)))
	}
	return err
}

// getChanges routes stream records from the compliance-table and the resources-table to the correct handler
func (sh *StreamHandler) getChanges(record *events.DynamoDBEventRecord) (interface{}, bool, error) {
	// Figure out where this record came from
	parsedSource, err := arn.Parse(record.EventSourceArn)
	if err != nil {
		return nil, false, errors.Wrapf(err, "unable to parse event source ARN %q", record.EventSourceArn)
	}

	// If it came from the compliance-table, it is a compliance status change
	if strings.HasPrefix(parsedSource.Resource, "table/panther-compliance") {
		change, err := sh.processComplianceSnapshot(record)
		return change, change != nil, err
	}
	// Otherwise, it must have come from the resource-table
	change, err := sh.processResourceChanges(record)
	return change, change != nil, err
}
