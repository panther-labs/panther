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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	cloudsecglue "github.com/panther-labs/panther/internal/compliance/awsglue"
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

func customUpdateLogTables(ctx context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	logger := lambdalogger.FromContext(ctx).With(
		zap.String("requestID", event.RequestID),
		zap.String("requestType", string(event.RequestType)),
		zap.String("stackID", event.StackID),
		zap.String("eventPhysicalResourceID", event.PhysicalResourceID),
	)
	logger.Info("received UpdateLogProcessorTables event", zap.String("requestType", string(event.RequestType)))
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		// It's important to always return this physicalResourceID
		const physicalResourceID = "custom:glue:update-log-processor-tables"
		var props UpdateLogProcessorTablesProperties
		if err := parseProperties(event.ResourceProperties, &props); err != nil {
			return physicalResourceID, nil, errors.Wrap(err, "failed to parse resource properties")
		}

		// FIXME: remove when this is supported by CloudFormation
		useAthena2()

		for db, desc := range pantherdb.Databases {
			if err := awsglue.EnsureDatabase(ctx, glueClient, db, desc); err != nil {
				return physicalResourceID, nil, errors.Wrapf(err, "failed to create database %s", db)
			}
		}

		if err := createCloudSecurityDDBTables(ctx); err != nil {
			return physicalResourceID, nil, err
		}

		logTypesInUse, err := apifunctions.ListLogTypes(ctx, lambdaClient)
		if err != nil {
			return physicalResourceID, nil, errors.Wrap(err, "failed to fetch required log types from Sources API")
		}
		client := datacatalog.Client{
			SQSAPI:   sqsClient,
			QueueURL: props.DataCatalogUpdaterQueueURL,
		}
		if err := client.SendSyncDatabase(ctx, event.RequestID, logTypesInUse); err != nil {
			return physicalResourceID, nil, errors.Wrap(err, "failed to update glue tables")
		}
		logger.Info("started database sync", zap.Strings("logTypes", logTypesInUse))
		return physicalResourceID, nil, nil
	case cfn.RequestDelete:
		// Deleting all log processing databases
		for db := range pantherdb.Databases {
			logger.Info("deleting database", zap.String("database", db))
			if _, err := awsglue.DeleteDatabase(glueClient, db); err != nil {
				if awsutils.IsAnyError(err, glue.ErrCodeEntityNotFoundException) {
					logger.Info("already deleted", zap.String("database", db))
				} else {
					return "", nil, errors.Wrapf(err, "failed deleting %s", db)
				}
			}
		}
		return event.PhysicalResourceID, nil, nil
	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func createCloudSecurityDDBTables(_ context.Context) error {
	endpoint, err := endpointResolver.EndpointFor("dynamodb", *awsSession.Config.Region)
	if err != nil {
		return errors.Wrapf(err, "failed to get endpoint information")
	}

	resourcesTableArn := arn.ARN{
		Partition: endpoint.PartitionID,
		Region:    aws.StringValue(awsSession.Config.Region),
		AccountID: env.AccountID,
		Service:   "dynamodb",
		Resource:  cloudsecglue.ResourcesTableDDB,
	}
	if err := cloudsecglue.CreateOrUpdateResourcesTable(glueClient, resourcesTableArn.String()); err != nil {
		return errors.Wrap(err, "failed to create resources table")
	}

	complianceTableArn := arn.ARN{
		Partition: endpoint.PartitionID,
		Region:    aws.StringValue(awsSession.Config.Region),
		AccountID: env.AccountID,
		Service:   "dynamodb",
		Resource:  cloudsecglue.ComplianceTableDDB,
	}

	if err := cloudsecglue.CreateOrUpdateComplianceTable(glueClient, complianceTableArn.String()); err != nil {
		return errors.Wrap(err, "failed to create compliance table")
	}
	return nil
}

// FIXME: remove when this is supported by CloudFormation and add to Panther WorkGroup CF
func useAthena2() {
	version := "Athena engine version 2"
	athenaClient := athena.New(awsSession)
	input := &athena.UpdateWorkGroupInput{
		ConfigurationUpdates: &athena.WorkGroupConfigurationUpdates{
			EngineVersion: &athena.EngineVersion{
				EffectiveEngineVersion: &version,
				SelectedEngineVersion:  &version,
			},
		},
		WorkGroup: aws.String("Panther"),
	}
	_, err := athenaClient.UpdateWorkGroup(input)
	if err != nil { // best effort, don't break the deploy in regions not supported!
		zap.L().Warn("useAthena2()", zap.Error(errors.Wrap(err, "failed to set Athena workgroup to version 2")))
	}
}
