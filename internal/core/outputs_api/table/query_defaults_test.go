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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

var mockQueryOutput = &dynamodb.QueryOutput{
	Items: []map[string]*dynamodb.AttributeValue{
		{
			"severity": {
				S: aws.String("INFO"),
			},
			"outputIds": {
				L: []*dynamodb.AttributeValue{{S: aws.String("outputId")}},
			},
		},
	},
}

var mockScanOutput = &dynamodb.ScanOutput{
	Items: []map[string]*dynamodb.AttributeValue{
		{
			"severity": {
				S: aws.String("INFO"),
			},
			"outputIds": {
				L: []*dynamodb.AttributeValue{{S: aws.String("outputId")}},
			},
		},
	},
}

func TestGetDefaults(t *testing.T) {
	mockClient := &mockDynamoDB{}
	table := &DefaultsTable{client: mockClient, Name: aws.String("defaultsTable")}

	expectedResult := []*models.DefaultOutputsItem{
		{
			Severity:  aws.String("INFO"),
			OutputIDs: []*string{aws.String("outputId")},
		},
	}
	mockClient.On("ScanPages", mock.Anything, mock.AnythingOfType("func(*dynamodb.ScanOutput, bool) bool")).Return(nil)

	result, err := table.GetDefaults()

	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)
}

func TestGetDefaultsClientError(t *testing.T) {
	mockClient := &mockDynamoDB{}
	table := &DefaultsTable{client: mockClient, Name: aws.String("defaultsTable")}

	mockClient.On("ScanPages", mock.Anything, mock.AnythingOfType("func(*dynamodb.ScanOutput, bool) bool")).Return(errors.New("error" +
		""))

	result, err := table.GetDefaults()
	require.Error(t, err)
	assert.IsType(t, &genericapi.AWSError{}, err)
	assert.Nil(t, result)
}
