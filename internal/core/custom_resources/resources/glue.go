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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/athenaviews"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/process"
	"github.com/panther-labs/panther/internal/log_analysis/gluetables"
)

type UpdateGlueTablesProperties struct {
	// TablesSignature should change every time the tables change (for CF master.yml this can be the Panther version)
	TablesSignature     string `validate:"required"`
	ProcessedDataBucket string `validate:"required"`
}

func customUpdateGlueTables(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	const resourceID = "custom:glue:update-tables"
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		var props UpdateGlueTablesProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return resourceID, nil, err
		}

		// ensure databases are all there
		for pantherDatabase, pantherDatabaseDescription := range awsglue.PantherDatabases {
			zap.L().Info("creating database", zap.String("database", pantherDatabase))
			if _, err := awsglue.CreateDatabase(glueClient, pantherDatabase, pantherDatabaseDescription); err != nil {
				var awsErr awserr.Error
				if errors.As(err, &awsErr) && awsErr.Code() == glue.ErrCodeAlreadyExistsException {
					zap.L().Info("database exists", zap.String("database", pantherDatabase))
				} else {
					return "", nil, errors.Wrapf(err, "failed creating database %s", pantherDatabase)
				}
			}
		}

		// update schemas for tables that are deployed
		deployedLogTables, err := gluetables.DeployedLogTables(glueClient)
		if err != nil {
			return "", nil, err
		}
		logTypes := make([]string, len(deployedLogTables))
		for i, logTable := range deployedLogTables {
			zap.L().Info("updating table", zap.String("database", logTable.DatabaseName()), zap.String("table", logTable.TableName()))

			// update catalog
			_, err := gluetables.CreateOrUpdateGlueTables(glueClient, props.ProcessedDataBucket, logTable)
			if err != nil {
				return "", nil, err
			}

			// collect the log types
			logTypes[i] = logTable.LogType()
		}

		// update the views with the new tables
		err = athenaviews.CreateOrReplaceViews(glueClient, athenaClient)
		if err != nil {
			return "", nil, errors.Wrap(err, "failed creating views")
		}

		// sync partitions via recursive lambda to avoid blocking the deployment
		if len(logTypes) > 0 {
			err = process.InvokeSyncGluePartitions(lambdaClient, logTypes)
			if err != nil {
				return "", nil, errors.Wrap(err, "failed invoking sync")
			}
		}

		return resourceID, nil, nil
	case cfn.RequestDelete:
		for pantherDatabase := range awsglue.PantherDatabases {
			zap.L().Info("deleting database", zap.String("database", pantherDatabase))
			if _, err := awsglue.DeleteDatabase(glueClient, pantherDatabase); err != nil {
				var awsErr awserr.Error
				if errors.As(err, &awsErr) && awsErr.Code() == glue.ErrCodeEntityNotFoundException {
					zap.L().Info("already deleted", zap.String("database", pantherDatabase))
				} else {
					return "", nil, errors.Wrapf(err, "failed deleting %s", pantherDatabase)
				}
			}
		}
		return event.PhysicalResourceID, nil, nil
	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}
