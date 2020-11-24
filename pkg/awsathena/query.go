package awsathena

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

	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/pkg/errors"
)

const (
	pollDelay = time.Second * 2
)

// RunQuery executes query, blocking until done
func RunQuery(client athenaiface.AthenaAPI, workgroup, database, sql string) (*athena.GetQueryResultsOutput, error) {
	startOutput, err := StartQuery(client, workgroup, database, sql)
	if err != nil {
		return nil, err
	}
	return WaitForResults(client, *startOutput.QueryExecutionId)
}

func StartQuery(client athenaiface.AthenaAPI, workgroup, database, sql string) (*athena.StartQueryExecutionOutput, error) {
	var startInput athena.StartQueryExecutionInput
	startInput.SetWorkGroup(workgroup)
	startInput.SetQueryString(sql)

	var startContext athena.QueryExecutionContext
	startContext.SetDatabase(database)
	startInput.SetQueryExecutionContext(&startContext)

	var resultConfig athena.ResultConfiguration
	startInput.SetResultConfiguration(&resultConfig)

	return client.StartQueryExecution(&startInput)
}

func WaitForResults(client athenaiface.AthenaAPI, queryExecutionID string) (queryResult *athena.GetQueryResultsOutput, err error) {
	isFinished := func() (executionOutput *athena.GetQueryExecutionOutput, done bool, err error) {
		executionOutput, err = Status(client, queryExecutionID)
		if err != nil {
			return nil, true, err
		}
		// not athena.QueryExecutionStateRunning or athena.QueryExecutionStateQueued
		switch *executionOutput.QueryExecution.Status.State {
		case
			athena.QueryExecutionStateSucceeded,
			athena.QueryExecutionStateCancelled:
			return executionOutput, true, nil
		case
			athena.QueryExecutionStateFailed:
			return executionOutput, true,
				errors.Errorf("query execution failed: %s", *executionOutput.QueryExecution.Status.StateChangeReason)
		default:
			return executionOutput, false, nil
		}
	}

	poll := func() (*athena.GetQueryExecutionOutput, error) {
		for {
			executionOutput, done, err := isFinished()
			if err != nil {
				return nil, err
			}
			if done {
				return executionOutput, nil
			}
			time.Sleep(pollDelay)
		}
	}

	executionOutput, err := poll()
	if err != nil {
		return nil, err
	}
	return Results(client, *executionOutput.QueryExecution.QueryExecutionId, nil, nil)
}

func Status(client athenaiface.AthenaAPI, queryExecutionID string) (executionOutput *athena.GetQueryExecutionOutput, err error) {
	var executionInput athena.GetQueryExecutionInput
	executionInput.SetQueryExecutionId(queryExecutionID)
	executionOutput, err = client.GetQueryExecution(&executionInput)
	if err != nil {
		return executionOutput, errors.WithStack(err)
	}
	return executionOutput, nil
}

func StopQuery(client athenaiface.AthenaAPI, queryExecutionID string) (executionOutput *athena.StopQueryExecutionOutput, err error) {
	var executionInput athena.StopQueryExecutionInput
	executionInput.SetQueryExecutionId(queryExecutionID)
	executionOutput, err = client.StopQueryExecution(&executionInput)
	if err != nil {
		return executionOutput, errors.WithStack(err)
	}
	return executionOutput, nil
}

func Results(client athenaiface.AthenaAPI, queryID string, nextToken *string,
	maxResults *int64) (queryResult *athena.GetQueryResultsOutput, err error) {

	var ip athena.GetQueryResultsInput
	ip.SetQueryExecutionId(queryID)
	ip.NextToken = nextToken
	ip.MaxResults = maxResults

	queryResult, err = client.GetQueryResults(&ip)
	if err != nil {
		return nil, errors.Wrapf(err, "athena failed reading results for: %s", queryID)
	}
	return queryResult, err
}
