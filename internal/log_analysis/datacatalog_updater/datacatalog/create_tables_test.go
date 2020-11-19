package datacatalog

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
	"context"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/sqs"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/testutils"
)

func TestSQS_CreateTables(t *testing.T) {
	initProcessTest()

	body := sqsTask{
		CreateTables: &CreateTablesEvent{
			LogTypes: []string{"AWS.S3ServerAccess", "AWS.VPCFlow"},
		},
	}
	marshalled, err := jsoniter.Marshal(body)
	require.NoError(t, err)
	msg := events.SQSMessage{
		Body: string(marshalled),
	}
	event := events.SQSEvent{Records: []events.SQSMessage{msg}}

	// Here comes the mocking
	mockGlueClient.On("CreateTable", mock.Anything).Return(&glue.CreateTableOutput{}, nil)
	// below called once for each database
	mockGlueClient.On("GetTablesPagesWithContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Twice()
	mockAthenaClient := &testutils.AthenaMock{}
	handler.AthenaClient = mockAthenaClient
	mockAthenaClient.On("StartQueryExecution", mock.Anything).Return(&athena.StartQueryExecutionOutput{
		QueryExecutionId: aws.String("test-query-1234"),
	}, nil)
	mockAthenaClient.On("GetQueryExecution", mock.Anything).Return(&athena.GetQueryExecutionOutput{
		QueryExecution: &athena.QueryExecution{
			QueryExecutionId: aws.String("test-query-1234"),
			Status: &athena.QueryExecutionStatus{
				State: aws.String(athena.QueryExecutionStateSucceeded),
			},
		},
	}, nil)
	mockAthenaClient.On("GetQueryResults", mock.Anything).Return(&athena.GetQueryResultsOutput{}, nil)

	err = handler.HandleSQSEvent(context.Background(), &event)
	require.NoError(t, err)
	mockGlueClient.AssertExpectations(t)
	mockAthenaClient.AssertExpectations(t)
}

func TestSQS_Sync(t *testing.T) {
	initProcessTest()

	body := &sqsTask{
		SyncDatabase: &SyncDatabaseEvent{
			TraceID: "testsync",
		},
	}
	marshalled, err := jsoniter.Marshal(body)
	require.NoError(t, err)
	msg := events.SQSMessage{
		Body: string(marshalled),
	}
	event := events.SQSEvent{Records: []events.SQSMessage{msg}}

	// Here comes the mocking
	mockGlueClient.On("CreateDatabaseWithContext", mock.Anything, mock.Anything).Return(&glue.CreateDatabaseOutput{}, nil)
	mockGlueClient.On("CreateTable", mock.Anything).Return(&glue.CreateTableOutput{}, nil)
	// below called once for each database
	mockGlueClient.On("GetTablesPagesWithContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(4)
	mockAthenaClient := &testutils.AthenaMock{}
	handler.AthenaClient = mockAthenaClient
	mockAthenaClient.On("StartQueryExecution", mock.Anything).Return(&athena.StartQueryExecutionOutput{
		QueryExecutionId: aws.String("test-query-1234"),
	}, nil)
	mockAthenaClient.On("GetQueryExecution", mock.Anything).Return(&athena.GetQueryExecutionOutput{
		QueryExecution: &athena.QueryExecution{
			QueryExecutionId: aws.String("test-query-1234"),
			Status: &athena.QueryExecutionStatus{
				State: aws.String(athena.QueryExecutionStateSucceeded),
			},
		},
	}, nil)
	mockAthenaClient.On("GetQueryResults", mock.Anything).Return(&athena.GetQueryResultsOutput{}, nil)

	// Sync
	mockSqsClient.On("SendMessageWithContext", mock.Anything, mock.Anything).Return(&sqs.SendMessageOutput{}, nil).Once()

	err = handler.HandleSQSEvent(context.Background(), &event)
	require.NoError(t, err)
	mockGlueClient.AssertExpectations(t)
	mockAthenaClient.AssertExpectations(t)
	mockSqsClient.AssertExpectations(t)
}
