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
	"fmt"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// UpdateIntegrationSettings makes an update to an integration from the UI.
//
// This endpoint updates attributes such as the behavior of the integration, or display information.
func (api API) UpdateIntegrationSettings(input *models.UpdateIntegrationSettingsInput) (*models.SourceIntegration, error) {
	// First get the current integration settings so that we can properly evaluate it
	integration, err := dynamoClient.GetIntegration(input.IntegrationID)
	if err != nil {
		return nil, err
	}

	// Validate the updated integration settings
	reason, passing, err := evaluateIntegrationFunc(api, &models.CheckIntegrationInput{
		// From existing integration
		AWSAccountID:    integration.AWSAccountID,
		IntegrationType: integration.IntegrationType,

		// From update integration request
		IntegrationLabel:  input.IntegrationLabel,
		EnableCWESetup:    input.CWEEnabled,
		EnableRemediation: input.RemediationEnabled,
		S3Bucket:          input.S3Bucket,
		S3Prefix:          input.S3Prefix,
		KmsKey:            input.KmsKey,
	})
	if err != nil {
		return nil, err
	}
	if !passing {
		zap.L().Warn("UpdateIntegration: resource has a misconfiguration",
			zap.Error(err),
			zap.String("reason", reason),
			zap.Any("input", input))
		return nil, &genericapi.InvalidInputError{Message: fmt.Sprintf("integration %s did not pass configuration check because of %s",
			*integration.AWSAccountID, reason)}
	}

	return dynamoClient.UpdateItem(&ddb.UpdateIntegrationItem{
		IntegrationID:      input.IntegrationID,
		IntegrationLabel:   input.IntegrationLabel,
		ScanIntervalMins:   input.ScanIntervalMins,
		CWEEnabled:         input.CWEEnabled,
		RemediationEnabled: input.RemediationEnabled,
		S3Bucket:           input.S3Bucket,
		S3Prefix:           input.S3Prefix,
		KmsKey:             input.KmsKey,
		LogTypes:           input.LogTypes,
	})
}

// UpdateIntegrationLastScanStart updates an integration when a new scan is started.
func (API) UpdateIntegrationLastScanStart(input *models.UpdateIntegrationLastScanStartInput) (*models.SourceIntegration, error) {
	return dynamoClient.UpdateItem(&ddb.UpdateIntegrationItem{
		IntegrationID:     input.IntegrationID,
		LastScanStartTime: input.LastScanStartTime,
		ScanStatus:        input.ScanStatus,
	})
}

// UpdateIntegrationLastScanEnd updates an integration when a scan ends.
func (API) UpdateIntegrationLastScanEnd(input *models.UpdateIntegrationLastScanEndInput) (*models.SourceIntegration, error) {
	return dynamoClient.UpdateItem(&ddb.UpdateIntegrationItem{
		IntegrationID:        input.IntegrationID,
		LastScanEndTime:      input.LastScanEndTime,
		LastScanErrorMessage: input.LastScanErrorMessage,
		ScanStatus:           input.ScanStatus,
	})
}
