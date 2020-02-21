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
	startResult *athena.StartQueryExecutionOutput
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

	aq.startResult, err = aq.Client.StartQueryExecution(&startInput)
	if err != nil {
		err = errors.Wrapf(err, "athena failed starting: %#v", *aq)
	}
	return err
}

func (aq *AthenaQuery) Wait() (err error) {
	executionOutput, err := aq.poll()
	if err != nil {
		return err
	}

	if *executionOutput.QueryExecution.Status.State == athena.QueryExecutionStateSucceeded {
		var ip athena.GetQueryResultsInput
		ip.SetQueryExecutionId(*aq.startResult.QueryExecutionId)

		aq.QueryResult, err = aq.Client.GetQueryResults(&ip)
		if err != nil {
			return errors.Wrapf(err, "athena failed getting results: %#v", *aq)
		}
	} else {
		return errors.Errorf("athena failed with status %s running: %#v", *executionOutput.QueryExecution.Status.State, *aq)
	}

	return nil
}

func (aq *AthenaQuery) poll() (executionOutput *athena.GetQueryExecutionOutput, err error) {
	var executionInput athena.GetQueryExecutionInput
	executionInput.SetQueryExecutionId(*aq.startResult.QueryExecutionId)
	for {
		executionOutput, err = aq.Client.GetQueryExecution(&executionInput)
		if err != nil {
			return nil, errors.Wrapf(err, "athena failed running: %#v", *aq)
		}
		// not athena.QueryExecutionStateRunning or athena.QueryExecutionStateQueued
		switch *executionOutput.QueryExecution.Status.State {
		case
			athena.QueryExecutionStateSucceeded,
			athena.QueryExecutionStateFailed,
			athena.QueryExecutionStateCancelled:
			return
		}
		time.Sleep(pollDelay)
	}
}
