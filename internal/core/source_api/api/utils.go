package api

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
	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
)

func integrationToItem(input *models.SourceIntegration) *ddb.Integration {
	// Initializing the fields common for all integration types
	item := &ddb.Integration{
		CreatedAtTime:    input.CreatedAtTime,
		CreatedBy:        input.CreatedBy,
		IntegrationID:    input.IntegrationID,
		IntegrationLabel: input.IntegrationLabel,
		IntegrationType:  input.IntegrationType,
	}
	item.LastEventReceived = input.LastEventReceived

	switch aws.StringValue(input.IntegrationType) {
	case models.IntegrationTypeAWS3:
		item.AWSAccountID = input.AWSAccountID
		item.S3Bucket = input.S3Bucket
		item.S3Prefix = input.S3Prefix
		item.KmsKey = input.KmsKey
		item.LogTypes = input.LogTypes
		item.StackName = input.StackName
		item.LogProcessingRole = aws.String(generateLogProcessingRoleArn(*input.AWSAccountID, *input.IntegrationLabel))
	case models.IntegrationTypeAWSScan:
		item.AWSAccountID = input.AWSAccountID
		item.CWEEnabled = input.CWEEnabled
		item.RemediationEnabled = input.RemediationEnabled
		item.ScanIntervalMins = input.ScanIntervalMins
		item.ScanStatus = input.ScanStatus
		item.EventStatus = input.EventStatus
		item.LastScanErrorMessage = input.LastScanErrorMessage
		item.LastScanStartTime = input.LastScanStartTime
		item.LastScanEndTime = input.LastScanEndTime
		item.StackName = input.StackName
	}
	return item
}

func itemToIntegration(item *ddb.Integration) *models.SourceIntegration {
	// Initializing the fields common for all integration types
	integration := &models.SourceIntegration{}
	integration.IntegrationID = item.IntegrationID
	integration.IntegrationType = item.IntegrationType
	integration.IntegrationLabel = item.IntegrationLabel
	integration.CreatedAtTime = item.CreatedAtTime
	integration.CreatedBy = item.CreatedBy
	integration.LastEventReceived = item.LastEventReceived

	switch aws.StringValue(item.IntegrationType) {
	case models.IntegrationTypeAWS3:
		integration.AWSAccountID = item.AWSAccountID
		integration.S3Bucket = item.S3Bucket
		integration.S3Prefix = item.S3Prefix
		integration.KmsKey = item.KmsKey
		integration.LogTypes = item.LogTypes
		integration.StackName = item.StackName
		integration.LogProcessingRole = item.LogProcessingRole
	case models.IntegrationTypeAWSScan:
		integration.AWSAccountID = item.AWSAccountID
		integration.CWEEnabled = item.CWEEnabled
		integration.RemediationEnabled = item.RemediationEnabled
		integration.ScanIntervalMins = item.ScanIntervalMins
		integration.ScanStatus = item.ScanStatus
		integration.EventStatus = item.EventStatus
		integration.LastScanStartTime = item.LastScanStartTime
		integration.LastScanEndTime = item.LastScanEndTime
		integration.LastScanErrorMessage = item.LastScanErrorMessage
		integration.StackName = item.StackName
	}
	return integration
}
