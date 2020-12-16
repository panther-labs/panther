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
	"math"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/utils"
)

type updateResult struct {
	AlertItems []*table.AlertItem
	Error      error
}

// UpdateAlertStatus modifies an alert's attributes.
func (api *API) UpdateAlertStatus(input *models.UpdateAlertStatusInput) (models.UpdateAlertStatusOutput, error) {
	// Run the update alert query
	if len(input.AlertIDs) == 0 {
		return models.UpdateAlertStatusOutput{}, nil
	}

	alertItems, err := api.dispatchUpdates(input, maxDDBPageSize)
	// Only process the most recent error. It would be extremely rare to have multiple errors
	// so we show one at a time to the user.
	if err != nil {
		return nil, err
	}

	alertRules := api.getAlertRules(alertItems)

	// Marshal to an alert summary
	return utils.AlertItemsToSummaries(alertItems, alertRules), nil
}

// dispatchUpdates - dispatches updates to alerts in in groups.
// Each group will process updates in series, but all groups are executed in parallel
func (api *API) dispatchUpdates(input *models.UpdateAlertStatusInput, maxPageSize int) ([]*table.AlertItem, error) {
	updateChannel := make(chan updateResult)
	alertCount := len(input.AlertIDs)

	// Get the total number of pages. This will be the number of goroutines to create
	pages := int(math.Ceil(float64(alertCount) / float64(maxPageSize)))

	// Slice up the AlertIDs into chunks to be processed in parallel
	for page := 0; page < pages; page++ {
		endIndex := int(math.Min(float64((page+1)*maxPageSize), float64(alertCount)))

		// create shallow copy of the input with chunked AlertIDs
		inputItems := &models.UpdateAlertStatusInput{
			Status:   input.Status,
			UserID:   input.UserID,
			AlertIDs: input.AlertIDs[page*maxPageSize : endIndex],
		}

		// Run the updates
		go api.dispatchUpdate(inputItems, updateChannel)
	}

	// Gather the results. If there were errors, we accumulate and let the routines complete
	alertItems := []*table.AlertItem{}
	errors := []error{}
	for page := 0; page < pages; page++ {
		result := <-updateChannel
		if result.Error != nil {
			errors = append(errors, result.Error)
			continue
		}
		alertItems = append(alertItems, result.AlertItems...)
	}

	// Return the first error we see. If there were to be any errors, they would most likely
	// be the same.
	if len(errors) > 0 {
		return nil, errors[0]
	}

	return alertItems, nil
}

// dispatch update routine
func (api *API) dispatchUpdate(input *models.UpdateAlertStatusInput, updateChannel chan updateResult) {
	alertItems, err := api.alertsDB.UpdateAlertStatus(input)
	updateChannel <- updateResult{
		AlertItems: alertItems,
		Error:      err,
	}
}
