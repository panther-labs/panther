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
	"time"

	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/box"
)

const (
	lambdaFunctionName = "panther-datacatalog-updater"
)

type SyncEvent struct {
	Sync         bool          // if true, this is a request to sync the partitions of the registered tables
	LogTypes     []string      // the log types to sync
	Continuation *Continuation // if not nil, start here
}

type Continuation struct {
	LogType           string
	DataType          models.DataType
	NextPartitionTime time.Time
}

// Sync does one logType then re-invokes, this way we have 15min/logType/sync and we do not overload the glue api
func Sync(event *SyncEvent, deadline time.Time) error {
	var zeroStartTime time.Time // setting the startTime to 0, means use createTime for the table

	// first, finish any pending work
	if event.Continuation != nil {
		startTime := event.Continuation.NextPartitionTime
		logType := event.Continuation.LogType
		logTable := registry.Lookup(logType).GlueTableMeta() // get the table description

		switch dataType := event.Continuation.DataType; dataType {
		case models.RuleData:
			// just finish rule matches, log already done
			deadlineExpired, err := syncTable(logTable.RuleTable(), event, startTime, deadline)
			if err != nil || deadlineExpired {
				return err
			}
		case models.RuleErrors:
			// finish the rule errors
			deadlineExpired, err := syncTable(logTable.RuleErrorTable(), event, startTime, deadline)
			if err != nil || deadlineExpired {
				return err
			}
		case models.LogData:
			// finish log table, then do rule table from zeroStartTime
			deadlineExpired, err := syncTable(logTable, event, startTime, deadline)
			if err != nil || deadlineExpired {
				return err
			}

			deadlineExpired, err = syncTable(logTable.RuleTable(), event, zeroStartTime, deadline)
			if err != nil || deadlineExpired {
				return err
			}
		default:
			return errors.New("Unknown data type " + dataType.String())
		}

		// advance to next log type now that we are done with continuation
		if len(event.LogTypes) > 1 {
			event.LogTypes = event.LogTypes[1:]
		} else {
			return nil // done!
		}
	}

	if len(event.LogTypes) > 0 {
		logType := event.LogTypes[0]
		logTable := registry.Lookup(logType).GlueTableMeta() // get the table description

		// sync table and companion rule match table
		deadlineExpired, err := syncTable(logTable, event, zeroStartTime, deadline)
		if err != nil || deadlineExpired {
			return err
		}

		deadlineExpired, err = syncTable(logTable.RuleTable(), event, zeroStartTime, deadline)
		if err != nil || deadlineExpired {
			return err
		}

		if len(event.LogTypes) > 1 { // more?
			err = InvokeSyncGluePartitions(lambdaClient, event.LogTypes[1:])
			if err != nil {
				return errors.Wrapf(err, "failed invoking sync on %v", event.LogTypes)
			}
		}
	}

	return nil
}

func syncTable(table *awsglue.GlueTableMetadata, event *SyncEvent, startTime, deadline time.Time) (bool, error) {
	zap.L().Info("sync'ing partitions for table", zap.String("database", table.DatabaseName()),
		zap.String("table", table.TableName()))

	nextPartitionTime, err := table.SyncPartitions(glueClient, s3Client, startTime, &deadline)
	if err != nil {
		return false, errors.Wrapf(err, "failed syncing %s.%s",
			table.DatabaseName(), table.TableName())
	}

	// deadline expired
	if nextPartitionTime != nil {
		continuation := &Continuation{
			LogType:           table.LogType(),
			DataType:          table.DataType(),
			NextPartitionTime: *nextPartitionTime,
		}
		err = invokeSyncGluePartitions(lambdaClient, event.LogTypes, continuation)
		if err != nil {
			return true, errors.Wrapf(err, "failed invoking sync on %v", event.LogTypes)
		}
		return true, nil
	}

	return false, nil
}

func invokeSyncGluePartitions(lambdaClient lambdaiface.LambdaAPI, logTypes []string, continuation *Continuation) error {
	zap.L().Info("invoking "+lambdaFunctionName, zap.Any("logTypes", logTypes), zap.Any("continuation", continuation))

	event := SyncEvent{
		Sync:         true,
		LogTypes:     logTypes,
		Continuation: continuation,
	}

	eventJSON, err := jsoniter.Marshal(event)
	if err != nil {
		err = errors.Wrapf(err, "failed to marshal %#v", event)
		return err
	}

	resp, err := lambdaClient.Invoke(&lambda.InvokeInput{
		FunctionName:   box.String(lambdaFunctionName),
		Payload:        eventJSON,
		InvocationType: box.String("Event"), // don't wait for response
	})
	if err != nil {
		err = errors.Wrapf(err, "failed to invoke %#v", event)
		return err
	}
	if resp.FunctionError != nil {
		err = errors.Errorf("%s: failed to invoke %#v", *resp.FunctionError, event)
		return err
	}

	return nil
}

func InvokeSyncGluePartitions(lambdaClient lambdaiface.LambdaAPI, logTypes []string) error {
	return invokeSyncGluePartitions(lambdaClient, logTypes, nil)
}
