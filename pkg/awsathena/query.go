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
	"github.com/pkg/errors"
)

const (
	pollDelay = time.Second * 2
)

type AthenaQuery struct {
	Session       *athena.Athena
	SQL           string
	S3ResultsPath *string // this can be nil, to use defaults
	Database      string
	QueryResult   *athena.GetQueryResultsOutput
	// internal state
	startResult *athena.StartQueryExecutionOutput
}

func NewAthenaQuery(sess *session.Session, database, sql string, s3Path *string) *AthenaQuery {
	return &AthenaQuery{
		Session:       athena.New(sess),
		SQL:           sql,
		S3ResultsPath: s3Path,
		Database:      database,
	}
}

func (aq *AthenaQuery) Run() (err error) {
	var qei athena.StartQueryExecutionInput
	qei.SetQueryString(aq.SQL)

	var qec athena.QueryExecutionContext
	qec.SetDatabase(aq.Database)
	qei.SetQueryExecutionContext(&qec)

	var rc athena.ResultConfiguration
	if aq.S3ResultsPath != nil {
		rc.SetOutputLocation(*aq.S3ResultsPath)
	}
	qei.SetResultConfiguration(&rc)

	aq.startResult, err = aq.Session.StartQueryExecution(&qei)
	if err != nil {
		err = errors.Wrapf(err, "athena failed running: %#v", *aq)
	}
	return err
}

func (aq *AthenaQuery) Wait() (err error) {
	var qei athena.GetQueryExecutionInput
	qei.SetQueryExecutionId(*aq.startResult.QueryExecutionId)

	var qeo *athena.GetQueryExecutionOutput

	for {
		qeo, err = aq.Session.GetQueryExecution(&qei)
		if err != nil {
			return errors.Wrapf(err, "athena failed running: %#v", *aq)
		}
		if *qeo.QueryExecution.Status.State != "RUNNING" {
			break
		}
		time.Sleep(pollDelay)
	}

	if *qeo.QueryExecution.Status.State == "SUCCEEDED" {
		var ip athena.GetQueryResultsInput
		ip.SetQueryExecutionId(*aq.startResult.QueryExecutionId)

		aq.QueryResult, err = aq.Session.GetQueryResults(&ip)
		if err != nil {
			return errors.Wrapf(err, "athena failed running: %#v", *aq)
		}
	} else {
		return errors.Errorf("athena failed with status %s running: %#v", *qeo.QueryExecution.Status.State, *aq)
	}

	return nil
}
