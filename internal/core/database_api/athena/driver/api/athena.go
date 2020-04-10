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

	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsathena"
)

const (
	pollWait = time.Second * 4
)

func (api API) ExecuteQuery(input *models.ExecuteQueryInput) (*models.ExecuteQueryOutput, error) {
	output := &models.ExecuteQueryOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	executeAsyncQueryOutput, err := api.ExecuteAsyncQuery(input)
	if err != nil || executeAsyncQueryOutput.ErrorMessage != "" { // either API error OR sql error
		output.Status = models.QueryFailed
		output.ErrorMessage = executeAsyncQueryOutput.ErrorMessage
		output.SQL = input.SQL
		return output, err
	}

	// poll
	for {
		time.Sleep(pollWait)
		getQueryStatusInput := &models.GetQueryStatusInput{
			QueryID: executeAsyncQueryOutput.QueryID,
		}
		getQueryStatusOutput, err := api.GetQueryStatus(getQueryStatusInput)
		if err != nil {
			return output, err
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

func (API) ExecuteAsyncQuery(input *models.ExecuteAsyncQueryInput) (*models.ExecuteAsyncQueryOutput, error) {
	output := &models.ExecuteAsyncQueryOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	startOutput, err := awsathena.StartQuery(athenaClient, input.DatabaseName, input.SQL, athenaS3ResultsPath)
	if err != nil {
		// try to dig out the athena error if there is one
		if athenaErr, ok := err.(*athena.InvalidRequestException); ok {
			output.ErrorMessage = athenaErr.Message()
			return output, nil // no lambda err
		}

		return output, err
	}

	output.QueryID = *startOutput.QueryExecutionId

	return output, nil
}

func (API) GetQueryStatus(input *models.GetQueryStatusInput) (*models.GetQueryStatusOutput, error) {
	output := &models.GetQueryStatusOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	executionStatus, err := awsathena.Status(athenaClient, input.QueryID)
	if err != nil {
		return output, err
	}

	output.SQL = *executionStatus.QueryExecution.Query
	output.Status = getQueryStatus(executionStatus)

	switch output.Status {
	case models.QueryFailed: // lambda succeeded BUT query failed (could be for many reasons)
		output.ErrorMessage = "Query failed: " + *executionStatus.QueryExecution.Status.StateChangeReason
	case models.QueryCanceled:
		output.ErrorMessage = "Query canceled"
	}

	return output, nil
}

func (api API) GetQueryResults(input *models.GetQueryResultsInput) (*models.GetQueryResultsOutput, error) {
	output := &models.GetQueryResultsOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	getStatusOutput, err := api.GetQueryStatus(&input.QueryIdentifier)
	if err != nil {
		return output, err
	}

	output.GetQueryStatusOutput = *getStatusOutput

	switch output.Status {
	case models.QuerySucceeded:
		var nextToken *string
		if input.PaginationToken != nil { // paging thru results
			nextToken = input.PaginationToken
		}
		err = getQueryResults(athenaClient, input.QueryID, output, nextToken, input.PageSize)
		if err != nil {
			return output, err
		}
	}

	return output, nil
}

func (api API) StopQuery(input *models.StopQueryInput) (*models.StopQueryOutput, error) {
	output := &models.StopQueryOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	_, err = awsathena.StopQuery(athenaClient, input.QueryID)
	if err != nil {
		return output, err
	}

	return api.GetQueryStatus(input)
}

func getQueryStatus(executionStatus *athena.GetQueryExecutionOutput) string {
	switch *executionStatus.QueryExecution.Status.State {
	case
		athena.QueryExecutionStateSucceeded:
		return models.QuerySucceeded
	case
		// failure modes
		athena.QueryExecutionStateFailed:
		return models.QueryFailed
	case
		athena.QueryExecutionStateCancelled:
		return models.QueryCanceled
	case
		// still going
		athena.QueryExecutionStateRunning,
		athena.QueryExecutionStateQueued:
		return models.QueryRunning
	default:
		panic("unknown athena status: " + *executionStatus.QueryExecution.Status.State)
	}
}

func getQueryResults(client athenaiface.AthenaAPI, queryID string,
	output *models.GetQueryResultsOutput, nextToken *string, maxResults *int64) (err error) {

	queryResult, err := awsathena.Results(client, queryID, nextToken, maxResults)
	if err != nil {
		return err
	}
	err = collectResults(queryResult, output)
	if err != nil {
		return err
	}
	return nil
}

func collectResults(queryResult *athena.GetQueryResultsOutput, output *models.GetQueryResultsOutput) (err error) {
	for _, row := range queryResult.ResultSet.Rows {
		var columns []*models.Column
		for _, col := range row.Data {
			columns = append(columns, &models.Column{
				Value: *col.VarCharValue,
			})
		}
		output.ResultsPage.Rows = append(output.ResultsPage.Rows, &models.Row{Columns: columns})
	}
	if err != nil {
		return errors.WithStack(err)
	}
	output.ResultsPage.NumRows = len(queryResult.ResultSet.Rows)
	output.ResultsPage.PaginationToken = queryResult.NextToken
	return nil
}
