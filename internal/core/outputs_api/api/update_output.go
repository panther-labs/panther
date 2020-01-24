package api

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

	outputType, err := getOutputType(input.OutputConfig)
	if err != nil {
		return nil, err
	}

	alertOutput := &models.AlertOutput{
		DisplayName:        input.DisplayName,
		LastModifiedBy:     input.UserID,
		LastModifiedTime:   aws.String(time.Now().Format(time.RFC3339)),
		OutputID:           input.OutputID,
		OutputType:         outputType,
		OutputConfig:       input.OutputConfig,
		DefaultForSeverity: input.DefaultForSeverity,
	}

	alertOutputItem, err := AlertOutputToItem(alertOutput)
	if err != nil {
		return nil, err
	}

	if alertOutputItem, err = outputsTable.UpdateOutput(alertOutputItem); err != nil {
		return nil, err
	}

	defaults, err := defaultsTable.GetDefaults()
	if err != nil {
		return nil, err
	}

	// Removing outputId from all defaults
	for _, defaultOutput := range defaults {
		var removed bool
		defaultOutput.OutputIDs, removed = removeFromSlice(defaultOutput.OutputIDs, input.OutputID)
		if removed {
			if err := defaultsTable.PutDefaults(defaultOutput); err != nil {
				return nil, err
			}
		}
	}

	if err := addToDefaults(input.DefaultForSeverity, input.OutputID); err != nil {
		return nil, err
	}

	alertOutput.CreatedBy = alertOutputItem.CreatedBy
	alertOutput.CreationTime = alertOutputItem.CreationTime
	alertOutput.VerificationStatus = alertOutputItem.VerificationStatus

	return alertOutput, nil
}

// Removes an item from a slice if it exists. Returns the resulting slice
// and a boolean indicating whether an item was removed or not
func removeFromSlice(slice []*string, item *string) ([]*string, bool) {
	new := make([]*string, 0, len(slice))
	for _, element := range slice {
		if *element != *item {
			new = append(new, element)
		}
	}
	return new, len(new) < len(slice)
}
