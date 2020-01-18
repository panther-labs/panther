package table

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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

var mockDefaultInputsItem = &models.DefaultOutputsItem{
	Severity:  aws.String("INFO"),
	OutputIDs: []*string{aws.String("outputId")},
}

func TestPutDefaults(t *testing.T) {
	mockClient := &mockDynamoDB{}
	table := &DefaultsTable{client: mockClient, Name: aws.String("defaultsTable")}

	expectedPutItem := &dynamodb.PutItemInput{
		TableName: aws.String("defaultsTable"),
		Item: map[string]*dynamodb.AttributeValue{
			"severity": {
				S: aws.String("INFO"),
			},
			"outputIds": {
				SS: aws.StringSlice([]string{"outputId"}),
			},
		},
	}

	mockClient.On("PutItem", expectedPutItem).Return((*dynamodb.PutItemOutput)(nil), nil)

	require.NoError(t, table.PutDefaults(mockDefaultInputsItem))
	mockClient.AssertExpectations(t)
}

func TestPutDefaultsClientError(t *testing.T) {
	mockClient := &mockDynamoDB{}
	table := &DefaultsTable{client: mockClient, Name: aws.String("defaultsTable")}
	mockClient.On("PutItem", mock.Anything).Return((*dynamodb.PutItemOutput)(nil), errors.New("testing"))

	require.Error(t, table.PutDefaults(mockDefaultInputsItem))
	mockClient.AssertExpectations(t)
}
