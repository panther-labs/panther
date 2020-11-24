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
	"sort"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

// ListLogTypes gets the current set of logTypes in use
func (api *API) ListLogTypes(_ *models.ListLogTypesInput) (*models.ListLogTypesOutput, error) {
	// this simply wraps the ListListIntegrations call
	listOutput, err := api.ListIntegrations(&models.ListIntegrationsInput{})
	if err != nil {
		return nil, err
	}

	return &models.ListLogTypesOutput{
		LogTypes: collectLogTypes(listOutput),
	}, nil
}

func collectLogTypes(listOutput []*models.SourceIntegration) []string {
	// collect them all in a set to ensure uniqueness
	logTypesSet := make(map[string]struct{})
	for _, integration := range listOutput {
		for _, logType := range integration.RequiredLogTypes() {
			logTypesSet[logType] = struct{}{}
		}
	}

	// make slice from map
	logTypes := make([]string, 0, len(logTypesSet))
	for logType := range logTypesSet {
		logTypes = append(logTypes, logType)
	}

	// ensure stable order
	sort.Strings(logTypes)

	return logTypes
}
