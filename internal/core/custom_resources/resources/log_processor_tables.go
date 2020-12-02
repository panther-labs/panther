package resources

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
	"fmt"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/core/source_api/apifunctions"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/datacatalog"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
	"github.com/panther-labs/panther/pkg/awsutils"
	"github.com/panther-labs/panther/pkg/lambdalogger"
)

type UpdateLogProcessorTablesProperties struct {
	DataCatalogUpdaterQueueURL string `validate:"required"`
}

func customUpdateLogProcessorTables(ctx context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	logger := lambdalogger.FromContext(ctx).With(
		zap.String("requestID", event.RequestID),
		zap.String("requestType", string(event.RequestType)),
		zap.String("stackID", event.StackID),
		zap.String("eventPhysicalResourceID", event.PhysicalResourceID),
	)
	logger.Debug("received UpdateLogProcessorTables event", zap.String("requestType", string(event.RequestType)))
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		// It's important to always return this physicalResourceID
		const physicalResourceID = "custom:glue:update-log-processor-tables"
		var props UpdateLogProcessorTablesProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			logger.Error("failed to parse resource properties", zap.Error(err))
			return physicalResourceID, nil, err
		}
		// Verify that all log processing databases are present
		for db, desc := range pantherdb.LogDatabases {
			if err := awsglue.EnsureDatabase(ctx, glueClient, db, desc); err != nil {
				return physicalResourceID, nil, errors.Wrapf(err, "failed to create database %s", db)
			}
		}

		requiredLogTypes, err := apifunctions.ListLogTypes(ctx, lambdaClient)
		if err != nil {
			logger.Error("failed to fetch required log types", zap.Error(err))
			return physicalResourceID, nil, errors.Wrap(err, "failed to fetch required log types from Sources API")
		}
		client := datacatalog.Client{
			SQSAPI:   sqsClient,
			QueueURL: props.DataCatalogUpdaterQueueURL,
		}
		if err := client.SendSyncDatabase(ctx, event.RequestID, requiredLogTypes); err != nil {
			logger.Error("failed to update glue tables", zap.Error(err))
			return physicalResourceID, nil, err
		}
		logger.Info("started database sync", zap.Strings("logTypes", requiredLogTypes))
		return physicalResourceID, nil, nil
	case cfn.RequestDelete:
		// Deleting all log processing databases
		for db := range pantherdb.LogDatabases {
			logger.Info("deleting database", zap.String("database", db))
			if _, err := awsglue.DeleteDatabase(glueClient, db); err != nil {
				if awsutils.IsAnyError(err, glue.ErrCodeEntityNotFoundException) {
					logger.Info("already deleted", zap.String("database", db))
				} else {
					logger.Error("failed to delete", zap.String("database", db))
					return "", nil, errors.Wrapf(err, "failed deleting %s", db)
				}
			}
		}
		return event.PhysicalResourceID, nil, nil
	default:
		logger.Error("unknown request type")
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}
