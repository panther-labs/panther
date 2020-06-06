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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/box"
)

const (
	lambdaFunctionName = "panther-datacatalog-updater"
)

type SyncEvent struct {
	Sync     bool     // if true, this is a request to sync the partitions of the registered tables
	LogTypes []string // the log types to sync
}

func Sync(event *SyncEvent) error {
	// Do one logType then re-invoke, this way we have 15min per logType per sync and
	// we do not overload the glue api which has a low TPS throttle.
	// NOTE: this can still timeout for tables with many partitions, if that happens use `mage glue:sync`
	// FIXME: we could fix this completely if we added a deadline to SyncPartitions() and resumed
	if len(event.LogTypes) > 0 {
		var zeroStartTime time.Time // setting the startTime to 0, means use createTime for the table
		logType := event.LogTypes[0]
		logTable := registry.AvailableParsers().LookupParser(logType).GlueTableMetadata // get the table description

		// sync partitions
		zap.L().Info("sync'ing partitions for table",
			zap.String("database", logTable.DatabaseName()),
			zap.String("table", logTable.TableName()))
		err := logTable.SyncPartitions(glueClient, s3Client, zeroStartTime)
		if err != nil {
			return errors.Wrapf(err, "failed syncing %s.%s",
				logTable.DatabaseName(), logTable.TableName())
		}
		ruleTable := logTable.RuleTable()
		zap.L().Info("sync'ing partitions for table",
			zap.String("database", ruleTable.DatabaseName()),
			zap.String("table", ruleTable.TableName()))
		err = ruleTable.SyncPartitions(glueClient, s3Client, zeroStartTime)
		if err != nil {
			return errors.Wrapf(err, "failed syncing %s.%s",
				ruleTable.DatabaseName(), ruleTable.TableName())
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

func InvokeSyncGluePartitions(lambdaClient lambdaiface.LambdaAPI, logTypes []string) error {
	zap.L().Info("invoking "+lambdaFunctionName, zap.Any("logTypes", logTypes))

	event := SyncEvent{
		Sync:     true,
		LogTypes: logTypes,
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
