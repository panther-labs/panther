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
	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

// SetDefaultOutputs sets the default outputs for an organization
func (API) SetDefaultOutputs(input *models.SetDefaultOutputsInput) (output *models.SetDefaultOutputsOutput, err error) {
	// Verify that the outputsIds exist
	for _, outputID := range input.OutputIDs {
		if _, err = outputsTable.GetOutput(outputID); err != nil {
			return nil, err
		}
	}

	item := &models.DefaultOutputsItem{
		Severity:  input.Severity,
		OutputIDs: input.OutputIDs,
	}

	if err = defaultsTable.PutDefaults(item); err != nil {
		return nil, err
	}

	output = &models.DefaultOutputs{
		Severity:  input.Severity,
		OutputIDs: input.OutputIDs,
	}

	return output, err
}
