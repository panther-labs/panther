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

	cloudsecglue "github.com/panther-labs/panther/internal/compliance/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
	"github.com/panther-labs/panther/pkg/awsutils"
)

type UpdateCloudSecurityTablesProperties struct {
	ResourcesTableARN  string
	ComplianceTableARN string
}

func customCloudSecurityTables(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		// It's important to always return this physicalResourceID
		const physicalResourceID = "custom:glue:update-cloud-security-tables"
		var props UpdateCloudSecurityTablesProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			zap.L().Error("failed to parse resource properties", zap.Error(err))
			return physicalResourceID, nil, err
		}
		if err := updateCloudSecurityTables(&props); err != nil {
			zap.L().Error("failed to update glue tables", zap.Error(err))
			return physicalResourceID, nil, err
		}
		return physicalResourceID, nil, nil
	case cfn.RequestDelete:
		zap.L().Info("deleting database", zap.String("database", pantherdb.CloudSecurityDatabase))
		if _, err := awsglue.DeleteDatabase(glueClient, pantherdb.CloudSecurityDatabase); err != nil {
			if awsutils.IsAnyError(err, glue.ErrCodeEntityNotFoundException) {
				zap.L().Info("already deleted", zap.String("database", pantherdb.CloudSecurityDatabase))
			} else {
				return "", nil, errors.Wrapf(err, "failed deleting %s", pantherdb.CloudSecurityDatabase)
			}
		}
		return event.PhysicalResourceID, nil, nil
	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func updateCloudSecurityTables(props *UpdateCloudSecurityTablesProperties) error {
	err := cloudsecglue.CreateOrUpdateCloudSecurityDatabase(glueClient)
	if err != nil {
		return err
	}

	err = cloudsecglue.CreateOrUpdateResourcesTable(glueClient, props.ResourcesTableARN)
	if err != nil {
		return err
	}

	err = cloudsecglue.CreateOrUpdateComplianceTable(glueClient, props.ComplianceTableARN)
	if err != nil {
		return err
	}

	return nil
}
