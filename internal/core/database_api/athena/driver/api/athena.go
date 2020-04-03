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
	minimalQueryWait = time.Second * 4
	pollWait = time.Second * 10
)

func (api API) ExecuteQuery(input *models.ExecuteQueryInput) (*models.ExecuteQueryOutput, error) {
	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	executeAsyncQueryOutput, err := api.ExecuteAsyncQuery((*models.ExecuteAsyncQueryInput)(input))
	if err != nil || executeAsyncQueryOutput.Status != models.QueryRunning {
		return (*models.ExecuteQueryOutput)(executeAsyncQueryOutput), err
	}

	// poll
	for {
		time.Sleep(pollWait)
		getQueryStatusInput := &models.GetQueryStatusInput{
			QueryID: executeAsyncQueryOutput.QueryID,
		}
		getQueryStatusOutput, err := api.GetQueryStatus(getQueryStatusInput)
		if err != nil {
			return (*models.ExecuteQueryOutput)(executeAsyncQueryOutput), err
		}
		if getQueryStatusOutput.Status != models.QueryRunning {
			break
		}
	}

	// get the results
	getQueryResultsInput := &models.GetQueryResultsInput{
		QueryID:            executeAsyncQueryOutput.QueryID,
	}
	getQueryResultsOutput, err := api.GetQueryResults(getQueryResultsInput)
	return (*models.ExecuteQueryOutput)(getQueryResultsOutput), err
}

func (API) ExecuteAsyncQuery(input *models.ExecuteAsyncQueryInput) (*models.ExecuteAsyncQueryOutput, error) {
	output := &models.ExecuteAsyncQueryOutput{}

	var err error
	defer func() {
		if err != nil {
			err = apiError(err) // lambda failed
		}
	}()

	query := awsathena.NewAthenaQuery(athenaClient, input.DatabaseName, input.SQL, athenaS3ResultsPath)
	err = query.Run()
	if err != nil {
		return output, err
	}

	output.QueryID = *query.StartExecutionOutput.QueryExecutionId

	time.Sleep(minimalQueryWait) // give query opportunity to finish and avoid a later polling step

	executionStatus, done, err := query.IsFinished()
	if err != nil {
		return output, err
	}
	output.Status = getQueryStatus(executionStatus)
	if done { // fill results
		switch  output.Status {
		case models.QuerySucceeded:
			err = getQueryResults(query.Client, executionStatus, (*models.GetQueryResultsOutput)(output),
				nil, input.ResultsMaxPageSize)
			if err != nil{
			return output, err
		    }
		case models.QueryFailed: // lambda succeeded BUT query failed (could be for many reasons)
			output.ErrorMessage = "Query failed: " + *executionStatus.QueryExecution.Status.StateChangeReason
		}
		}
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
	output.Status = getQueryStatus(executionStatus)
	return output, nil
}

func (API) GetQueryResults(input *models.GetQueryResultsInput) (*models.GetQueryResultsOutput, error) {
	output := &models.GetQueryResultsOutput{}

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
	output.Status = getQueryStatus(executionStatus)

	switch output.Status {
		case models.QuerySucceeded :
			var nextToken *string
			if input.PaginationToken != nil { // paging thru results
				nextToken = input.PaginationToken
			}
			err = getQueryResults(athenaClient, executionStatus, output, nextToken, input.ResultsMaxPageSize)
			if err != nil {
				return output, err
			}
	case models.QueryFailed: // lambda succeeded BUT query failed (could be for many reasons)
		output.ErrorMessage = "Query failed: " + *executionStatus.QueryExecution.Status.StateChangeReason
	}

	return output, nil
}

func getQueryStatus(executionStatus *athena.GetQueryExecutionOutput) string {
	switch *executionStatus.QueryExecution.Status.State {
	case
		athena.QueryExecutionStateSucceeded:
		return models.QuerySucceeded
	case
		// failure modes
		athena.QueryExecutionStateFailed,
		athena.QueryExecutionStateCancelled:
		return models.QueryFailed
	case
		// still going
		athena.QueryExecutionStateRunning,
		athena.QueryExecutionStateQueued:
		return models.QueryRunning
	default:
		panic("unknown athena status: " + *executionStatus.QueryExecution.Status.State)
	}
}

func getQueryResults(client athenaiface.AthenaAPI, executionStatus *athena.GetQueryExecutionOutput,
	output *models.GetQueryResultsOutput, nextToken *string, maxResults *int64) (err error) {

	queryResult, err := awsathena.Results(client, executionStatus, nextToken, maxResults)
	if err != nil {
		return err
	}
	err = collectResults(queryResult, output, maxResults)
	if err != nil {
		return err
	}
	return nil
}

func collectResults(queryResult *athena.GetQueryResultsOutput, output *models.GetQueryResultsOutput, maxResults *int64) (err error) {
	for _, row := range queryResult.ResultSet.Rows {
		var columns []*models.Column
		for _, col := range row.Data {
			columns = append(columns, &models.Column{
				Value: *col.VarCharValue,
			})
		}
		output.Rows = append(output.Rows, &models.Row{Columns: columns})
	}
	if err != nil {
		return errors.WithStack(err)
	}
	output.NumRows = len(queryResult.ResultSet.Rows)
	if output.NumRows > 0 && (maxResults == nil || int(*maxResults) == output.NumRows) { // could be more!
		output.PaginationToken = queryResult.NextToken
	} else {
		output.PaginationToken = nil // no more
	}
	return nil
}
