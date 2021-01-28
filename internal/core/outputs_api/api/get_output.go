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
	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

// GetOutput retrieves a single alert output
func (API) GetOutput(input *models.GetOutputInput) (*models.GetOutputOutput, error) {
	item, err := outputsTable.GetOutput(input.OutputID)
	if err != nil {
		return nil, err
	}

	alertOutput, err := ItemToAlertOutput(item)
	if err != nil {
		return nil, err
	}
	redactOutput(alertOutput.OutputConfig)
	configureOutputFallbacks(alertOutput)

	return alertOutput, nil
}
