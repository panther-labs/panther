package api

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

var mockGetDefaultsInput = &models.GetDefaultOutputsInput{}

func TestGetDefaultOutputs(t *testing.T) {
	mockDefaultsTable := &mockDefaultsTable{}
	defaultsTable = mockDefaultsTable

	items := []*models.DefaultOutputsItem{
		{
			Severity:  aws.String("INFO"),
			OutputIDs: []*string{aws.String("outputId1")},
		},
		{
			Severity:  aws.String("WARN"),
			OutputIDs: []*string{aws.String("outputId2")},
		},
	}

	expectedResult := &models.GetDefaultOutputsOutput{
		Defaults: []*models.DefaultOutputs{
			{
				Severity:  aws.String("INFO"),
				OutputIDs: []*string{aws.String("outputId1")},
			},
			{
				Severity:  aws.String("WARN"),
				OutputIDs: []*string{aws.String("outputId2")},
			},
		},
	}
	mockDefaultsTable.On("GetDefaults").Return(items, nil)

	result, err := (API{}).GetDefaultOutputs(mockGetDefaultsInput)

	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	mockDefaultsTable.AssertExpectations(t)
}

func TestGetDefaultOutputsEmpty(t *testing.T) {
	mockDefaultsTable := &mockDefaultsTable{}
	defaultsTable = mockDefaultsTable

	items := []*models.DefaultOutputsItem{
		{
			Severity: aws.String("HIGH"),
			// DDB returns the below structure instead of populated empty slice
			OutputIDs: nil,
		},
	}
	// Verify that the result has the an empty slice in the Default field instead of nil
	expectedResult := &models.GetDefaultOutputsOutput{Defaults: []*models.DefaultOutputs{}}

	mockDefaultsTable.On("GetDefaults").Return(items, nil)

	result, err := (API{}).GetDefaultOutputs(mockGetDefaultsInput)

	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	mockDefaultsTable.AssertExpectations(t)
}

func TestGetDefaultOutputsTableError(t *testing.T) {
	mockDefaultsTable := &mockDefaultsTable{}
	defaultsTable = mockDefaultsTable
	mockDefaultsTable.On("GetDefaults").Return(([]*models.DefaultOutputsItem)(nil), errors.New("error"))

	result, err := (API{}).GetDefaultOutputs(mockGetDefaultsInput)

	require.Error(t, err)
	assert.Nil(t, result)
	mockDefaultsTable.AssertExpectations(t)
}
