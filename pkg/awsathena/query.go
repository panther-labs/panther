package awsathena

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
func RunQuery(client athenaiface.AthenaAPI, database, sql string, s3Path *string) (*athena.GetQueryResultsOutput, error) {
	startOutput, err := StartQuery(client, database, sql, s3Path)
	if err != nil {
		return nil, err
	}
	return WaitForResults(client, *startOutput.QueryExecutionId)
}

func StartQuery(client athenaiface.AthenaAPI, database, sql string, s3Path *string) (*athena.StartQueryExecutionOutput, error) {
	var startInput athena.StartQueryExecutionInput
	startInput.SetQueryString(sql)

	var startContext athena.QueryExecutionContext
	startContext.SetDatabase(database)
	startInput.SetQueryExecutionContext(&startContext)

	var resultConfig athena.ResultConfiguration
	if s3Path != nil {
		resultConfig.SetOutputLocation(*s3Path)
	}
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
			athena.QueryExecutionStateFailed,
			athena.QueryExecutionStateCancelled:
			return executionOutput, true, nil
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
