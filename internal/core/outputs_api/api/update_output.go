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
	"time"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// UpdateOutput updates the alert output with the new values
func (API) UpdateOutput(input *models.UpdateOutputInput) (*models.UpdateOutputOutput, error) {
	existingOutput, err := outputsTable.GetOutputByName(input.DisplayName)
	if err != nil {
		return nil, err
	}

	// if there is already a different output with the same 'displayName', fail the operation
	if existingOutput != nil && *existingOutput.OutputID != *input.OutputID {
		return nil, &genericapi.AlreadyExistsError{
			Message: "A destination with the name" + *input.DisplayName + " already exists, please choose another display name"}
	}

	// Next check the outputConfig, this is to support partial updates of the outputConfig
	var newConfig *models.OutputConfig
	if input.OutputConfig != nil {
		// Get the existing configuration
		existingOutput, err = outputsTable.GetOutput(input.OutputID)
		if err != nil {
			return nil, &genericapi.DoesNotExistError{
				Message: "A destination with the ID " + *input.OutputID + " does not exist."}
		}
		// Decrypt the existing configuration
		decryptedConfig := &models.OutputConfig{}
		err = encryptionKey.DecryptConfig(existingOutput.EncryptedConfig, decryptedConfig)
		if err != nil {
			return nil, &genericapi.InternalError{
				Message: "Unable to decrypt existing configuration for output " + *input.DisplayName,
			}
		}
		// Merge the old config with the new config
		newConfig, err = mergeConfigs(decryptedConfig, input.OutputConfig)
		if err != nil {
			return nil, err
		}
	}

	alertOutput := &models.AlertOutput{
		DisplayName:        input.DisplayName,
		LastModifiedBy:     input.UserID,
		LastModifiedTime:   aws.String(time.Now().Format(time.RFC3339)),
		OutputID:           input.OutputID,
		OutputConfig:       newConfig,
		DefaultForSeverity: input.DefaultForSeverity,
		AlertTypes:         input.AlertTypes,
	}

	alertOutputItem, err := AlertOutputToItem(alertOutput)
	if err != nil {
		return nil, err
	}

	if alertOutputItem, err = outputsTable.UpdateOutput(alertOutputItem); err != nil {
		return nil, err
	}

	// Returning the result of the update operation
	if alertOutput, err = ItemToAlertOutput(alertOutputItem); err != nil {
		return nil, err
	}
	redactOutput(alertOutput.OutputConfig)
	configureOutputFallbacks(alertOutput)

	return alertOutput, nil
}
