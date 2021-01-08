package table

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/stretchr/testify/assert"

	"github.com/panther-labs/panther/pkg/genericapi"
)

var mockOutputID = aws.String("outputID")

type mockPutClient struct {
	dynamodbiface.DynamoDBAPI
	conditionalErr bool
	serviceErr     bool
}

func (m *mockPutClient) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	if m.conditionalErr && input.ConditionExpression != nil {
		return nil, awserr.New(
			dynamodb.ErrCodeConditionalCheckFailedException, "attribute does not exist", nil)
	}
	if m.serviceErr {
		return nil, awserr.New(
			dynamodb.ErrCodeResourceNotFoundException, "table does not exist", nil)
	}
	return &dynamodb.PutItemOutput{}, nil
}

func TestPutOutputDoesNotExist(t *testing.T) {
	table := &OutputsTable{client: &mockPutClient{conditionalErr: true}}
	err := table.PutOutput(&AlertOutputItem{OutputID: mockOutputID})
	assert.NotNil(t, err.(*genericapi.DoesNotExistError))
}

func TestPutOutputServiceError(t *testing.T) {
	table := &OutputsTable{client: &mockPutClient{serviceErr: true}}
	err := table.PutOutput(&AlertOutputItem{OutputID: mockOutputID})
	assert.NotNil(t, err.(*genericapi.AWSError))
}

func TestPutOutput(t *testing.T) {
	table := &OutputsTable{client: &mockPutClient{}}
	assert.Nil(t, table.PutOutput(&AlertOutputItem{OutputID: mockOutputID}))
}
