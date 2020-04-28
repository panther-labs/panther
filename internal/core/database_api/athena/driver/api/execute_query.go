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

	"github.com/panther-labs/panther/api/lambda/database/models"
)

const (
	pollWait = time.Second * 2
)

func (api API) ExecuteQuery(input *models.ExecuteQueryInput) (*models.ExecuteQueryOutput, error) {
	var output models.ExecuteQueryOutput

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	executeAsyncQueryOutput, err := api.ExecuteAsyncQuery(input)
	if err != nil || executeAsyncQueryOutput.SQLError != "" { // either API error OR sql error
		output.Status = models.QueryFailed
		output.QueryStatus = executeAsyncQueryOutput.QueryStatus
		output.SQL = input.SQL
		return &output, err
	}

	// poll
	getQueryStatusInput := &models.GetQueryStatusInput{
		QueryID: executeAsyncQueryOutput.QueryID,
	}
	for {
		time.Sleep(pollWait)
		getQueryStatusOutput, err := api.GetQueryStatus(getQueryStatusInput)
		if err != nil {
			return &output, err
		}
		if getQueryStatusOutput.Status != models.QueryRunning {
			break
		}
	}

	// get the results
	getQueryResultsInput := &models.GetQueryResultsInput{}
	getQueryResultsInput.QueryID = executeAsyncQueryOutput.QueryID
	return api.GetQueryResults(getQueryResultsInput)
}
