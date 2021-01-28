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
	"github.com/aws/aws-lambda-go/lambdacontext"
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
	mockGlueClient.On("CreateTableWithContext", mock.Anything, mock.Anything).Return(&glue.CreateTableOutput{}, nil)
	mockAthenaClient := &testutils.AthenaMock{}
	handler.AthenaClient = mockAthenaClient
	// is called once for each Panther database
	mockAthenaClient.On("ListTableMetadataPagesWithContext",
		mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(4)

	err = handler.HandleSQSEvent(lambdacontext.NewContext(context.Background(), &lambdacontext.LambdaContext{}), &event)
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
	// below called once for the log database and once for the cloudsecurity database to get the base schemas
	mockGlueClient.On("GetTablesPagesWithContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(2)
	mockAthenaClient := &testutils.AthenaMock{}
	handler.AthenaClient = mockAthenaClient
	// is called once for each Panther database
	mockAthenaClient.On("ListTableMetadataPagesWithContext", mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(4)

	// Sync databases
	mockSqsClient.On("SendMessageWithContext", mock.Anything, mock.Anything).Return(&sqs.SendMessageOutput{}, nil).Once()

	err = handler.HandleSQSEvent(lambdacontext.NewContext(context.Background(), &lambdacontext.LambdaContext{}), &event)
	require.NoError(t, err)
	mockGlueClient.AssertExpectations(t)
	mockAthenaClient.AssertExpectations(t)
	mockSqsClient.AssertExpectations(t)
}
