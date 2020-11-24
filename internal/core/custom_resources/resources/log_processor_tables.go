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
	"github.com/panther-labs/panther/pkg/awsutils"
)

type UpdateLogProcessorTablesProperties struct {
	// TablesSignature should change every time the tables change (for CF master.yml this can be the Panther version)
	TablesSignature            string `validate:"required"`
	DataCatalogUpdaterQueueURL string `validate:"required"`
}

func customUpdateLogProcessorTables(ctx context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		// It's important to always return this physicalResourceID
		const physicalResourceID = "custom:glue:update-log-processor-tables"
		var props UpdateLogProcessorTablesProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			zap.L().Error("failed to parse resource properties", zap.Error(err))
			return physicalResourceID, nil, err
		}
		requiredLogTypes, err := apifunctions.ListLogTypes(ctx, lambdaClient)
		if err != nil {
			return physicalResourceID, nil, errors.Wrap(err, "failed to fetch required log types from Sources API")
		}
		client := datacatalog.Client{
			SQSAPI:   sqsClient,
			QueueURL: props.DataCatalogUpdaterQueueURL,
		}
		if err := client.SendSyncDatabase(ctx, "", requiredLogTypes); err != nil {
			zap.L().Error("failed to update glue tables", zap.Error(err))
			return physicalResourceID, nil, err
		}
		return physicalResourceID, nil, nil
	case cfn.RequestDelete:
		for pantherDatabase := range awsglue.PantherDatabases {
			zap.L().Info("deleting database", zap.String("database", pantherDatabase))
			if _, err := awsglue.DeleteDatabase(glueClient, pantherDatabase); err != nil {
				if awsutils.IsAnyError(err, glue.ErrCodeEntityNotFoundException) {
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
