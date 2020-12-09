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
	"context"
	"fmt"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/internal/log_analysis/datacatalog_updater/datacatalog"
	"github.com/panther-labs/panther/pkg/genericapi"
)

var (
	updateIntegrationInternalError = &genericapi.InternalError{Message: "Failed to update source, please try again later"}
)

// UpdateIntegrationSettings makes an update to an integration from the UI.
//
// This endpoint updates attributes such as the behavior of the integration, or display information.
func (api API) UpdateIntegrationSettings(input *models.UpdateIntegrationSettingsInput) (*models.SourceIntegration, error) {
	// First get the current existingItem settings so that we can properly evaluate it
	existingItem, err := getItem(input.IntegrationID)
	if err != nil {
		return nil, err
	}

	if err = api.validateUniqueConstraints(existingItem, input); err != nil {
		return nil, err
	}

	// Validate the updates
	reason, passing, err := evaluateIntegrationFunc(api, &models.CheckIntegrationInput{
		// Same as the existing integration item
		AWSAccountID:    existingItem.AWSAccountID,
		IntegrationType: existingItem.IntegrationType,

		// From update existingItem request
		IntegrationLabel:  input.IntegrationLabel,
		EnableCWESetup:    input.CWEEnabled,
		EnableRemediation: input.RemediationEnabled,
		S3Bucket:          input.S3Bucket,
		S3PrefixLogTypes:  input.S3PrefixLogTypes,
		KmsKey:            input.KmsKey,
		SqsConfig:         input.SqsConfig,
	})
	if err != nil {
		return nil, err
	}
	if !passing {
		zap.L().Warn("UpdateIntegration: resource has a misconfiguration",
			zap.Error(err),
			zap.String("reason", reason),
			zap.Any("input", input))
		return nil, &genericapi.InvalidInputError{
			Message: fmt.Sprintf("source %s did not pass configuration check because of %s",
				existingItem.AWSAccountID, reason),
		}
	}

	if err := updateTables(existingItem, input); err != nil {
		zap.L().Error("failed to update tables", zap.Error(err))
		return nil, updateIntegrationInternalError
	}

	updateIntegrationDBItem(existingItem, input)

	if existingItem.IntegrationType == models.IntegrationTypeSqs {
		err := UpdateSourceSqsQueue(
			existingItem.IntegrationID, existingItem.SqsConfig.AllowedPrincipalArns, existingItem.SqsConfig.AllowedSourceArns)
		if err != nil {
			zap.L().Error("failed to update integration", zap.Error(err))
			return nil, err
		}
	}

	if err := dynamoClient.PutItem(existingItem); err != nil {
		zap.L().Error("failed to put item in ddb", zap.Error(err))
		return nil, updateIntegrationInternalError
	}

	existingIntegration := itemToIntegration(existingItem)

	return existingIntegration, nil
}

func (api API) validateUniqueConstraints(existingIntegrationItem *ddb.Integration, input *models.UpdateIntegrationSettingsInput) error {
	existingIntegrations, err := api.ListIntegrations(&models.ListIntegrationsInput{})
	if err != nil {
		zap.L().Error("failed to fetch integrations", zap.Error(errors.WithStack(err)))
		return updateIntegrationInternalError
	}
	for _, existingIntegration := range existingIntegrations {
		if existingIntegration.IntegrationType == existingIntegrationItem.IntegrationType &&
			existingIntegration.IntegrationID != existingIntegrationItem.IntegrationID {

			switch existingIntegration.IntegrationType {
			case models.IntegrationTypeAWS3:
				if existingIntegration.AWSAccountID == existingIntegrationItem.AWSAccountID &&
					existingIntegration.IntegrationLabel == input.IntegrationLabel {
					// Log sources for same account need to have different labels
					return &genericapi.InvalidInputError{
						Message: fmt.Sprintf("Log source for account %s with label %s already onboarded",
							existingIntegrationItem.AWSAccountID,
							input.IntegrationLabel),
					}
				}
			case models.IntegrationTypeSqs:
				if existingIntegration.IntegrationLabel == input.IntegrationLabel {
					// Sqs sources need to have different labels
					return &genericapi.InvalidInputError{
						Message: fmt.Sprintf("Integration with label %s already exists", input.IntegrationLabel),
					}
				}
			}
		}
	}
	return nil
}

func updateIntegrationDBItem(item *ddb.Integration, input *models.UpdateIntegrationSettingsInput) {
	switch item.IntegrationType {
	case models.IntegrationTypeAWSScan:
		item.IntegrationLabel = input.IntegrationLabel
		item.ScanIntervalMins = input.ScanIntervalMins
		item.CWEEnabled = input.CWEEnabled
		item.RemediationEnabled = input.RemediationEnabled
	case models.IntegrationTypeAWS3:
		if input.IntegrationLabel != "" {
			item.IntegrationLabel = input.IntegrationLabel
			item.StackName = getStackName(models.IntegrationTypeAWS3, input.IntegrationLabel)
			item.LogProcessingRole = generateLogProcessingRoleArn(item.AWSAccountID, input.IntegrationLabel)
		}

		item.S3Bucket = input.S3Bucket
		item.KmsKey = input.KmsKey
		item.S3PrefixLogTypes = input.S3PrefixLogTypes
		// These fields are replaced by S3PrefixLogTypes, clear them to avoid confusion when checking old records.
		item.S3Prefix = ""
		item.LogTypes = nil
	case models.IntegrationTypeSqs:
		item.IntegrationLabel = input.IntegrationLabel
		item.SqsConfig.LogTypes = input.SqsConfig.LogTypes
		item.SqsConfig.AllowedSourceArns = input.SqsConfig.AllowedSourceArns
		item.SqsConfig.AllowedPrincipalArns = input.SqsConfig.AllowedPrincipalArns
	}
}

// UpdateIntegrationLastScanStart updates an integration when a new scan is started.
func (API) UpdateIntegrationLastScanStart(input *models.UpdateIntegrationLastScanStartInput) error {
	existingIntegration, err := getItem(input.IntegrationID)
	if err != nil {
		return err
	}

	existingIntegration.LastScanStartTime = &input.LastScanStartTime
	existingIntegration.ScanStatus = input.ScanStatus
	err = dynamoClient.PutItem(existingIntegration)
	if err != nil {
		return &genericapi.InternalError{Message: "Failed updating the integration last scan start"}
	}
	return nil
}

// UpdateIntegrationLastScanEnd updates an integration when a scan ends.
func (API) UpdateIntegrationLastScanEnd(input *models.UpdateIntegrationLastScanEndInput) error {
	existingIntegration, err := getItem(input.IntegrationID)
	if err != nil {
		return err
	}

	existingIntegration.LastScanEndTime = &input.LastScanEndTime
	existingIntegration.LastScanErrorMessage = input.LastScanErrorMessage
	existingIntegration.ScanStatus = input.ScanStatus
	err = dynamoClient.PutItem(existingIntegration)
	if err != nil {
		return &genericapi.InternalError{Message: "Failed updating the integration last scan end"}
	}
	return nil
}

func getItem(integrationID string) (*ddb.Integration, error) {
	item, err := dynamoClient.GetItem(integrationID)
	if err != nil {
		return nil, &genericapi.InternalError{Message: "Encountered issue while updating integration"}
	}

	if item == nil {
		return nil, &genericapi.DoesNotExistError{Message: "existingIntegration does not exist"}
	}
	return item, nil
}

func updateTables(item *ddb.Integration, input *models.UpdateIntegrationSettingsInput) error {
	var existingLogTypes, newLogTypes []string
	switch item.IntegrationType {
	case models.IntegrationTypeAWS3:
		existingLogTypes = item.S3PrefixLogTypes.LogTypes()
		newLogTypes = input.S3PrefixLogTypes.LogTypes()
	case models.IntegrationTypeSqs:
		existingLogTypes = item.SqsConfig.LogTypes
		newLogTypes = input.SqsConfig.LogTypes
	}

	// If the user hasn't added new log types to the integration
	// don't create new tables
	if !newLogsAdded(existingLogTypes, newLogTypes) {
		return nil
	}

	client := datacatalog.Client{
		SQSAPI:   sqsClient,
		QueueURL: env.DataCatalogUpdaterQueueURL,
	}
	err := client.SendCreateTablesForLogTypes(context.TODO(), newLogTypes...)
	if err != nil {
		return errors.Wrap(err, "failed to create Glue tables")
	}
	return nil
}

// Returns True if user has added new logs, false otherwise
func newLogsAdded(old, new []string) bool {
	for i := range new {
		found := false
		for j := range old {
			if new[i] == old[j] {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}
