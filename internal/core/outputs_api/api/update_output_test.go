package api

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/outputs_api/table"
)

var mockUpdateOutputInput = &models.UpdateOutputInput{
	OutputID:           aws.String("outputId"),
	DisplayName:        aws.String("displayName"),
	UserID:             aws.String("userId"),
	OutputConfig:       &models.OutputConfig{},
	DefaultForSeverity: aws.StringSlice([]string{"CRITICAL", "HIGH"}),
}

func TestUpdateOutput(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey

	alertOutputItem := &table.AlertOutputItem{
		OutputID:        aws.String("outputId"),
		DisplayName:     aws.String("displayName"),
		CreatedBy:       aws.String("createdBy"),
		CreationTime:    aws.String("createdTime"),
		LastModifiedBy:  aws.String("userId"),
		OutputType:      aws.String("sns"),
		AlertTypes:      []string{"RULE", "RULE_ERROR", "POLICY"},
		EncryptedConfig: make([]byte, 1),
	}

	mockOutputsTable.On("UpdateOutput", mock.Anything).Return(alertOutputItem, nil)
	mockOutputsTable.On("GetOutputByName", aws.String("displayName")).Return(nil, nil)
	mockOutputsTable.On("GetOutput", aws.String("outputId")).Return(alertOutputItem, nil)
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)
	mockEncryptionKey.On("DecryptConfig", mock.Anything, mock.Anything).Return(nil)

	result, err := (API{}).UpdateOutput(mockUpdateOutputInput)

	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, aws.String("outputId"), result.OutputID)
	assert.Equal(t, aws.String("displayName"), result.DisplayName)
	assert.Equal(t, aws.String("createdBy"), result.CreatedBy)
	assert.Equal(t, aws.String("userId"), result.LastModifiedBy)
	assert.Equal(t, aws.String("sns"), result.OutputType)
	assert.Equal(t, []string{"RULE", "RULE_ERROR", "POLICY"}, result.AlertTypes)

	mockOutputsTable.AssertExpectations(t)
}

func TestUpdateOutputOtherItemExists(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable

	preExistingAlertItem := &table.AlertOutputItem{
		OutputID: aws.String("outputId-2"),
	}

	mockOutputsTable.On("GetOutputByName", aws.String("displayName")).Return(preExistingAlertItem, nil)

	result, err := (API{}).UpdateOutput(mockUpdateOutputInput)

	assert.Error(t, err)
	assert.Nil(t, result)
	mockOutputsTable.AssertExpectations(t)
}

func TestUpdateSameOutputOutput(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey

	alertOutputItem := &table.AlertOutputItem{
		OutputID:        aws.String("outputId"),
		DisplayName:     aws.String("displayName"),
		CreatedBy:       aws.String("createdBy"),
		CreationTime:    aws.String("createdTime"),
		LastModifiedBy:  aws.String("userId"),
		OutputType:      aws.String("sns"),
		EncryptedConfig: make([]byte, 1),
	}

	preExistingAlertItem := &table.AlertOutputItem{
		OutputID: mockUpdateOutputInput.OutputID,
	}

	mockOutputsTable.On("UpdateOutput", mock.Anything).Return(alertOutputItem, nil)
	mockOutputsTable.On("GetOutputByName", aws.String("displayName")).Return(preExistingAlertItem, nil)
	mockOutputsTable.On("GetOutput", aws.String("outputId")).Return(preExistingAlertItem, nil)
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)
	mockEncryptionKey.On("DecryptConfig", mock.Anything, mock.Anything).Return(nil)

	result, err := (API{}).UpdateOutput(mockUpdateOutputInput)

	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, aws.String("outputId"), result.OutputID)
	assert.Equal(t, aws.String("displayName"), result.DisplayName)
	assert.Equal(t, aws.String("createdBy"), result.CreatedBy)
	assert.Equal(t, aws.String("userId"), result.LastModifiedBy)
	assert.Equal(t, aws.String("sns"), result.OutputType)

	mockOutputsTable.AssertExpectations(t)
}
