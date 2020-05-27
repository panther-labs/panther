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
	"time"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/athenaviews"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/gluetables"
)

type UpdateGlueTablesProperties struct {
	// TablesSignature should change every time the tables change (for SAR this can be the Panther version)
	TablesSignature     string `validate:"required"`
	ProcessedDataBucket string `validate:"required"`
}

func customUpdateGlueTables(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	const resourceID = "custom:glue:update-tables"
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		glueClient := getGlueClient()
		s3Client := getS3Client()
		athenaClient := getAthenaClient()

		var props UpdateGlueTablesProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return resourceID, nil, err
		}

		// ensure databases are all there
		for pantherDatabase, pantherDatabaseDescription := range awsglue.PantherDatabases {
			zap.L().Info("creating database", zap.String("database", pantherDatabase))
			_, err := awsglue.CreateDatabase(glueClient, pantherDatabase, pantherDatabaseDescription)
			if err != nil {
				if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == glue.ErrCodeAlreadyExistsException {
					zap.L().Info("database exists", zap.String("database", pantherDatabase))
				} else {
					return "", nil, errors.Wrapf(err, "failed creating database %s", pantherDatabase)
				}
			}
		}

		// update schemas for tables that are deployed
		var zeroStartTime time.Time // setting the startTime to 0, means use createTime for the table
		deployedLogTables, err := gluetables.DeployedLogTables(glueClient)
		if err != nil {
			return "", nil, err
		}
		for _, logTable := range deployedLogTables {
			zap.L().Info("updating table", zap.String("database", logTable.DatabaseName()), zap.String("table", logTable.TableName()))

			// update catalog
			ruleTable, err := gluetables.CreateOrUpdateGlueTables(glueClient, props.ProcessedDataBucket, logTable)
			if err != nil {
				return "", nil, err
			}

			// sync partitions
			err = logTable.SyncPartitions(glueClient, s3Client, zeroStartTime)
			if err != nil {
				return "", nil, errors.Wrapf(err, "failed syncing %s.%s",
					logTable.DatabaseName(), logTable.TableName())
			}
			err = ruleTable.SyncPartitions(glueClient, s3Client, zeroStartTime)
			if err != nil {
				return "", nil, errors.Wrapf(err, "failed syncing %s.%s",
					ruleTable.DatabaseName(), ruleTable.TableName())
			}
		}

		// update the views with the new tables
		err = athenaviews.CreateOrReplaceViews(glueClient, athenaClient)
		if err != nil {
			return "", nil, errors.Wrap(err, "failed creating views")
		}

		return resourceID, nil, nil

	case cfn.RequestDelete:
		glueClient := getGlueClient()
		for pantherDatabase := range awsglue.PantherDatabases {
			zap.L().Info("deleting database", zap.String("database", pantherDatabase))
			_, err := awsglue.DeleteDatabase(glueClient, pantherDatabase)
			if err != nil {
				if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == glue.ErrCodeEntityNotFoundException {
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
