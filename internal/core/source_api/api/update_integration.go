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
	// First get the current existingIntegrationItem settings so that we can properly evaluate it
	existingIntegrationItem, err := getItem(input.IntegrationID)
	if err != nil {
		return nil, err
	}

	if err = api.validateUniqueConstraints(existingIntegrationItem, input); err != nil {
		return nil, err
	}

	// Validate the updated existingIntegrationItem settings
	reason, passing, err := evaluateIntegrationFunc(api, &models.CheckIntegrationInput{
		// From existing existingIntegrationItem
		AWSAccountID:    existingIntegrationItem.AWSAccountID,
		IntegrationType: existingIntegrationItem.IntegrationType,

		// From update existingIntegrationItem request
		IntegrationLabel:  input.IntegrationLabel,
		EnableCWESetup:    input.CWEEnabled,
		EnableRemediation: input.RemediationEnabled,
		S3Bucket:          input.S3Bucket,
		S3Prefix:          input.S3Prefix,
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
				existingIntegrationItem.AWSAccountID, reason),
		}
	}

	if err := updateTables(existingIntegrationItem, input); err != nil {
		zap.L().Error("failed to update tables", zap.Error(err))
		return nil, updateIntegrationInternalError
	}

	if err := normalizeIntegration(existingIntegrationItem, input); err != nil {
		zap.L().Error("failed to normalize integration", zap.Error(err))
		return nil, err
	}

	if err := dynamoClient.PutItem(existingIntegrationItem); err != nil {
		zap.L().Error("failed to put item in ddb", zap.Error(err))
		return nil, updateIntegrationInternalError
	}

	existingIntegration := itemToIntegration(existingIntegrationItem)

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

				if existingIntegration.S3Bucket == input.S3Bucket && existingIntegration.S3Prefix == input.S3Prefix {
					return &genericapi.InvalidInputError{
						Message: "An S3 integration with the same S3 bucket and prefix already exists.",
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

func normalizeIntegration(item *ddb.Integration, input *models.UpdateIntegrationSettingsInput) error {
	switch item.IntegrationType {
	case models.IntegrationTypeAWSScan:
		item.IntegrationLabel = input.IntegrationLabel
		item.ScanIntervalMins = input.ScanIntervalMins
		item.CWEEnabled = input.CWEEnabled
		item.RemediationEnabled = input.RemediationEnabled
	case models.IntegrationTypeAWS3:
		item.S3Bucket = input.S3Bucket
		item.S3Prefix = input.S3Prefix
		item.KmsKey = input.KmsKey
		item.LogTypes = input.LogTypes
	case models.IntegrationTypeSqs:
		item.IntegrationLabel = input.IntegrationLabel
		item.SqsConfig.LogTypes = input.SqsConfig.LogTypes

		newAllowedPrincipals := input.SqsConfig.AllowedPrincipalArns
		newAllowedSources := input.SqsConfig.AllowedSourceArns
		item.SqsConfig.AllowedSourceArns = newAllowedSources
		item.SqsConfig.AllowedPrincipalArns = newAllowedPrincipals
		if err := UpdateSourceSqsQueue(item.IntegrationID, newAllowedPrincipals, newAllowedSources); err != nil {
			return updateIntegrationInternalError
		}
	}
	return nil
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
		existingLogTypes = item.LogTypes
		newLogTypes = input.LogTypes
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
