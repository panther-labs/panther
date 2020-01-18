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
	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// DeleteOutput removes the alert output configuration
func (API) DeleteOutput(input *models.DeleteOutputInput) error {
	defaults, err := defaultsTable.GetDefaults()
	if err != nil {
		return err
	}

	for _, defaultOutput := range defaults {
		for index, outputID := range defaultOutput.OutputIDs {
			if *outputID == *input.OutputID {
				if aws.BoolValue(input.Force) {
					// Remove outputID from the list of outputs
					ids := defaultOutput.OutputIDs
					defaultOutput.OutputIDs = append(ids[:index], ids[index+1:]...)

					// Update defaults table
					if err = defaultsTable.PutDefaults(defaultOutput); err != nil {
						return err
					}
				} else {
					return &genericapi.InUseError{Message: "This destination is currently in use, please try again in a few seconds"}
				}
			}
		}
	}

	return outputsTable.DeleteOutput(input.OutputID)
}
