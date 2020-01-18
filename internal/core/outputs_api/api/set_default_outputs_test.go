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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

var mockSetDefaultsInput = &models.SetDefaultOutputsInput{
	Severity:  aws.String("INFO"),
	OutputIDs: aws.StringSlice([]string{"outputId1", "outputId2"}),
}

func TestSetDefaults(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	mockDefaultsTable := &mockDefaultsTable{}

	outputsTable = mockOutputsTable
	defaultsTable = mockDefaultsTable

	expectedDefaults := &models.DefaultOutputsItem{
		Severity:  aws.String("INFO"),
		OutputIDs: aws.StringSlice([]string{"outputId1", "outputId2"}),
	}

	expectedResult := &models.DefaultOutputs{
		Severity:  aws.String("INFO"),
		OutputIDs: aws.StringSlice([]string{"outputId1", "outputId2"}),
	}

	mockOutputsTable.On("GetOutput", aws.String("outputId1")).Return(&models.AlertOutputItem{}, nil)
	mockOutputsTable.On("GetOutput", aws.String("outputId2")).Return(&models.AlertOutputItem{}, nil)
	mockDefaultsTable.On("PutDefaults", expectedDefaults).Return(nil)

	result, err := (API{}).SetDefaultOutputs(mockSetDefaultsInput)

	require.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	mockOutputsTable.AssertExpectations(t)
	mockDefaultsTable.AssertExpectations(t)
}

func TestSetDefaultsFailureWhenOutputDoesntExist(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	mockDefaultsTable := &mockDefaultsTable{}

	outputsTable = mockOutputsTable
	defaultsTable = mockDefaultsTable

	mockOutputsTable.On("GetOutput", mock.Anything, mock.Anything).Return((*models.AlertOutputItem)(nil), errors.New("error"))

	result, err := (API{}).SetDefaultOutputs(mockSetDefaultsInput)

	require.Error(t, err)
	assert.Nil(t, result)
	mockOutputsTable.AssertExpectations(t)
	mockDefaultsTable.AssertExpectations(t)
}

func TestSetDefaultsFailureWhenPutFails(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	mockDefaultsTable := &mockDefaultsTable{}

	outputsTable = mockOutputsTable
	defaultsTable = mockDefaultsTable

	mockOutputsTable.On("GetOutput", mock.Anything, mock.Anything).Return(&models.AlertOutputItem{}, nil)
	mockDefaultsTable.On("PutDefaults", mock.Anything).Return(errors.New("error"))

	result, err := (API{}).SetDefaultOutputs(mockSetDefaultsInput)

	require.Error(t, err)
	assert.Nil(t, result)
	mockOutputsTable.AssertExpectations(t)
	mockDefaultsTable.AssertExpectations(t)
}
