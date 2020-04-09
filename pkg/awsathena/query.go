package awsathena

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
		err = errors.Wrapf(err, "athena failed to start query: %#v", *aq)
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
			return errors.Wrapf(err, "athena failed reading results: %#v", *aq)
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
