package ddb

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

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

// ScanIntegrations returns all enabled integrations based on type (if type is specified).
// It performs a DDB scan of the entire table with a filter expression.
func (ddb *DDB) ScanIntegrations(integrationType *string) ([]*Integration, error) {
	scanInput := &dynamodb.ScanInput{
		TableName: &ddb.TableName,
	}
	if integrationType != nil {
		filterExpression := expression.Name("integrationType").Equal(expression.Value(integrationType))
		expr, err := expression.NewBuilder().WithFilter(filterExpression).Build()
		if err != nil {
			return nil, errors.Wrap(err, "failed to build filter expression")
		}
		scanInput.FilterExpression = expr.Filter()
		scanInput.ExpressionAttributeNames = expr.Names()
		scanInput.ExpressionAttributeValues = expr.Values()
	}

	output, err := ddb.Client.Scan(scanInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to scan table")
	}

	var integrations []*Integration
	if err := dynamodbattribute.UnmarshalListOfMaps(output.Items, &integrations); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal scan results")
	}

	return integrations, nil
}

func (ddb *DDB) ListS3SourcesWithBucket(ctx context.Context, bucket string) ([]models.SourceIntegration, error) {
	typeFilter := expression.Name("integrationType").Equal(expression.Value(models.IntegrationTypeAWS3))
	bucketFilter := expression.Name("s3Bucket").Equal(expression.Value(bucket))
	expr, err := expression.NewBuilder().WithFilter(typeFilter).WithFilter(bucketFilter).Build()
	if err != nil {
		return nil, errors.Wrap(err, "failed to build filter expression")
	}

	scanInput := &dynamodb.ScanInput{
		TableName:                 &ddb.TableName,
		FilterExpression:          expr.Filter(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}
	output, err := ddb.Client.ScanWithContext(ctx, scanInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to scan table")
	}

	var integrations []*Integration
	if err := dynamodbattribute.UnmarshalListOfMaps(output.Items, &integrations); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal scan results")
	}

	result := make([]models.SourceIntegration, 0, len(integrations))
	for _, item := range integrations {
		integ := ItemToIntegration(item)
		result = append(result, *integ)
	}
	return result, nil
}

// Deprecated. This should not be exported but only be used by functions that directly interact with DynamoDB,
// in the ddb package.
// These functions should return our domain model `models.SourceIntegration`.
func ItemToIntegration(item *Integration) *models.SourceIntegration {
	// Initializing the fields common for all integration types
	integration := &models.SourceIntegration{}
	integration.IntegrationID = item.IntegrationID
	integration.IntegrationType = item.IntegrationType
	integration.IntegrationLabel = item.IntegrationLabel
	integration.CreatedAtTime = item.CreatedAtTime
	integration.CreatedBy = item.CreatedBy
	integration.LastEventReceived = item.LastEventReceived
	integration.PantherVersion = item.PantherVersion
	switch item.IntegrationType {
	case models.IntegrationTypeAWS3:
		integration.AWSAccountID = item.AWSAccountID
		integration.S3Bucket = item.S3Bucket
		integration.S3PrefixLogTypes = item.S3PrefixLogTypes
		if len(integration.S3PrefixLogTypes) == 0 {
			// Backwards compatibility: Use the old fields, maybe the info is there.
			s3prefixLogTypes := models.S3PrefixLogtypesMapping{S3Prefix: item.S3Prefix, LogTypes: item.LogTypes}
			integration.S3PrefixLogTypes = models.S3PrefixLogtypes{s3prefixLogTypes}
		}
		integration.KmsKey = item.KmsKey
		integration.StackName = item.StackName
		integration.LogProcessingRole = item.LogProcessingRole
		integration.ManagedBucketNotifications = item.ManagedBucketNotifications
	case models.IntegrationTypeAWSScan:
		integration.AWSAccountID = item.AWSAccountID
		integration.CWEEnabled = item.CWEEnabled
		integration.RemediationEnabled = item.RemediationEnabled
		integration.ScanIntervalMins = item.ScanIntervalMins
		integration.ScanStatus = item.ScanStatus
		integration.S3Bucket = item.S3Bucket
		integration.LogProcessingRole = item.LogProcessingRole
		integration.EventStatus = item.EventStatus
		integration.LastScanStartTime = item.LastScanStartTime
		integration.LastScanEndTime = item.LastScanEndTime
		integration.LastScanErrorMessage = item.LastScanErrorMessage
		integration.StackName = item.StackName
		integration.Enabled = item.Enabled
		integration.RegionIgnoreList = item.RegionIgnoreList
		integration.ResourceTypeIgnoreList = item.ResourceTypeIgnoreList
		integration.ResourceRegexIgnoreList = item.ResourceRegexIgnoreList
	case models.IntegrationTypeSqs:
		integration.SqsConfig = &models.SqsConfig{
			S3Bucket:             item.SqsConfig.S3Bucket,
			LogProcessingRole:    item.SqsConfig.LogProcessingRole,
			QueueURL:             item.SqsConfig.QueueURL,
			LogTypes:             item.SqsConfig.LogTypes,
			AllowedPrincipalArns: item.SqsConfig.AllowedPrincipalArns,
			AllowedSourceArns:    item.SqsConfig.AllowedSourceArns,
		}
	}
	return integration
}
