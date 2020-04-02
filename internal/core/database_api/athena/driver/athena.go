package driver

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/pkg/awsathena"
)

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

const (
	minimalQueryWait = time.Second * 4
)

func DoQuery(client athenaiface.AthenaAPI, input *models.DoQueryInput) (*models.DoQueryOutput, error) {
	output := &models.DoQueryOutput{}

	var err error
	defer func() {
		if err != nil {
			output.Status = models.QueryFailed
			output.ErrorMessage = "DoQuery failed" // simple error message for lambda caller
		}
	}()

	query := awsathena.NewAthenaQuery(client, input.DatabaseName, input.SQL, nil)
	err = query.Run()
	if err != nil {
		return output, err
	}
	err = query.Wait()
	if err != nil {
		return output, err
	}

	err = collectResults(query.QueryResult, (*models.GetQueryResultsOutput)(output), nil)
	if err != nil {
		return output, err
	}

	return output, nil
}

func StartQuery(client athenaiface.AthenaAPI, input *models.StartQueryInput) (*models.StartQueryOutput, error) {
	output := &models.StartQueryOutput{}

	var err error
	defer func() {
		if err != nil {
			output.Status = models.QueryFailed
			output.ErrorMessage = "StartQuery failed" // simple error message for lambda caller
		}
	}()

	query := awsathena.NewAthenaQuery(client, input.DatabaseName, input.SQL, nil)
	err = query.Run()
	if err != nil {
		return output, err
	}

	output.QueryID = *query.StartExecutionOutput.QueryExecutionId

	time.Sleep(minimalQueryWait) // give query opportunity to finish and avoid a later polling step

	executionStatus, done, err := query.Done()
	if err != nil {
		return output, err
	}
	output.Status = getQueryStatus(executionStatus)
	if done { // fill results
		if output.Status == models.QuerySucceeded {
			err = getQueryResults(query.Client, executionStatus, &output.GetQueryResultsOutput, nil, input.MaxResults)
			if err != nil {
				return output, err
			}
		}
	}
	return output, nil
}

func GetQueryStatus(client athenaiface.AthenaAPI, input *models.GetQueryStatusInput) (*models.GetQueryStatusOutput, error) {
	output := &models.GetQueryStatusOutput{}

	var err error
	defer func() {
		if err != nil {
			output.ErrorMessage = "GetQueryStatus failed" // simple error message for lambda caller
		}
	}()

	executionStatus, err := awsathena.Status(client, input.QueryID)
	if err != nil {
		return output, err
	}
	output.Status = getQueryStatus(executionStatus)
	return output, nil
}

func GetQueryResults(client athenaiface.AthenaAPI, input *models.GetQueryResultsInput) (*models.GetQueryResultsOutput, error) {
	output := &models.GetQueryResultsOutput{}

	var err error
	defer func() {
		if err != nil {
			output.ErrorMessage = "GetQueryResults failed" // simple error message for lambda caller
		}
	}()

	executionStatus, err := awsathena.Status(client, input.QueryID)
	if err != nil {
		return output, err
	}
	output.Status = getQueryStatus(executionStatus)

	if output.Status == models.QuerySucceeded {
		var nextToken *string
		if input.PaginationToken != "" { // paging thru results
			nextToken = &input.PaginationToken
		}
		err = getQueryResults(client, executionStatus, output, nextToken, input.MaxResults)
		if err != nil {
			return output, err
		}
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
	output.Status = models.QuerySucceeded
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
		output.PaginationToken = aws.StringValue(queryResult.NextToken)
	} else {
		output.PaginationToken = "" // no more
	}
	return nil
}
