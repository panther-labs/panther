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

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/athena/athenaiface"
	"github.com/pkg/errors"
)

const (
	pollDelay = time.Second * 2
)

type AthenaQuery struct {
	Client        athenaiface.AthenaAPI
	SQL           string
	S3ResultsPath *string // this can be nil, to use defaults
	Database      string
	QueryResult   *athena.GetQueryResultsOutput
	// internal state
	StartExecutionOutput *athena.StartQueryExecutionOutput
}

func NewAthenaQuery(sess *session.Session, database, sql string, s3Path *string) *AthenaQuery {
	return &AthenaQuery{
		Client:        athena.New(sess),
		SQL:           sql,
		S3ResultsPath: s3Path,
		Database:      database,
	}
}

func (aq *AthenaQuery) Run() (err error) {
	var startInput athena.StartQueryExecutionInput
	startInput.SetQueryString(aq.SQL)

	var startContext athena.QueryExecutionContext
	startContext.SetDatabase(aq.Database)
	startInput.SetQueryExecutionContext(&startContext)

	var resultConfig athena.ResultConfiguration
	if aq.S3ResultsPath != nil {
		resultConfig.SetOutputLocation(*aq.S3ResultsPath)
	}
	startInput.SetResultConfiguration(&resultConfig)

	aq.StartExecutionOutput, err = aq.Client.StartQueryExecution(&startInput)
	if err != nil {
		err = errors.Wrapf(err, "athena failed to start query: %#v", *aq)
	}
	return err
}

func (aq *AthenaQuery) Wait() (err error) {
	executionOutput, err := aq.poll()
	if err != nil {
		return err
	}
	return aq.Results(executionOutput, nil, nil)
}

func (aq *AthenaQuery) poll() (*athena.GetQueryExecutionOutput, error) {
	for {
		executionOutput, done, err := aq.Done()
		if err != nil {
			return nil, err
		}
		if done {
			return executionOutput, nil
		}
		time.Sleep(pollDelay)
	}
}

func (aq *AthenaQuery) Done() (executionOutput *athena.GetQueryExecutionOutput, done bool, err error) {
	executionOutput, err = aq.Status()
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
	}
	return executionOutput, false, nil
}

func (aq *AthenaQuery) Status() (executionOutput *athena.GetQueryExecutionOutput, err error) {
	return Status(aq.Client, *aq.StartExecutionOutput.QueryExecutionId)
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

func (aq *AthenaQuery) Results(executionOutput *athena.GetQueryExecutionOutput, nextToken *string, maxResults *int64) (err error) {
	aq.QueryResult, err = Results(aq.Client, executionOutput, nextToken, maxResults)
	return err
}

func Results(client athenaiface.AthenaAPI, executionOutput *athena.GetQueryExecutionOutput,
	nextToken *string, maxResults *int64) (queryResult *athena.GetQueryResultsOutput, err error) {

	if *executionOutput.QueryExecution.Status.State == athena.QueryExecutionStateSucceeded {
		var ip athena.GetQueryResultsInput
		ip.SetQueryExecutionId(*executionOutput.QueryExecution.QueryExecutionId)
		ip.NextToken = nextToken
		ip.MaxResults = maxResults

		queryResult, err = client.GetQueryResults(&ip)
		if err != nil {
			return nil, errors.Wrapf(err, "athena failed reading results: %s",
				*executionOutput.QueryExecution.QueryExecutionId)
		}
		return queryResult, err
	}

	return nil, errors.Errorf("athena failed with status %s running: %s",
		*executionOutput.QueryExecution.Status.State, *executionOutput.QueryExecution.QueryExecutionId)
}
