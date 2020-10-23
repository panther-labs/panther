package process

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
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/athena"
	"github.com/aws/aws-sdk-go/service/glue"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/testutils"
)

func TestSQS_CreateTables(t *testing.T) {
	initProcessTest()

	body := CreateTablesMessage{
		LogTypes: []string{"AWS.S3ServerAccess", "AWS.VPCFlow"},
	}
	marshalled, err := jsoniter.Marshal(body)
	require.NoError(t, err)
	msg := events.SQSMessage{
		Body: string(marshalled),
		MessageAttributes: map[string]events.SQSMessageAttribute{
			PantherMessageType: {
				DataType:    *CreateTableMessageAttribute.DataType,
				StringValue: CreateTableMessageAttribute.StringValue,
			},
		},
	}
	event := events.SQSEvent{Records: []events.SQSMessage{msg}}

	// Here comes the mocking
	mockGlueClient.On("CreateTable", mock.Anything).Return(&glue.CreateTableOutput{}, nil)
	mockGlueClient.On("GetTablesPagesWithContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockAthenaClient := &testutils.AthenaMock{}
	athenaClient = mockAthenaClient
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

	err = handleSQSEvent(event)
	require.NoError(t, err)
}
