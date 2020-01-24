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
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

var mockUpdateOutputInput = &models.UpdateOutputInput{
	OutputID:           aws.String("outputId"),
	DisplayName:        aws.String("displayName"),
	UserID:             aws.String("userId"),
	OutputConfig:       &models.OutputConfig{Sns: &models.SnsConfig{}},
	DefaultForSeverity: aws.StringSlice([]string{"CRITICAL", "HIGH"}),
}

func TestUpdateOutput(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey
	mockDefaultsTable := &mockDefaultsTable{}
	defaultsTable = mockDefaultsTable

	alertOutputItem := &models.AlertOutputItem{
		OutputID:           aws.String("outputId"),
		DisplayName:        aws.String("displayName"),
		CreatedBy:          aws.String("createdBy"),
		CreationTime:       aws.String("createdTime"),
		OutputType:         aws.String("sns"),
		VerificationStatus: aws.String(models.VerificationStatusSuccess),
		EncryptedConfig:    make([]byte, 1),
	}

	mockDefaultsTable.On("GetDefaults", mock.Anything).Return([]*models.DefaultOutputsItem{}, nil)
	mockDefaultsTable.On("GetDefault", mock.Anything).Return(&models.DefaultOutputsItem{}, nil)
	mockDefaultsTable.On("PutDefaults", mock.Anything).Return(nil)
	mockOutputsTable.On("UpdateOutput", mock.Anything).Return(alertOutputItem, nil)
	mockOutputsTable.On("GetOutputByName", aws.String("displayName")).Return(nil, nil)
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)
	mockEncryptionKey.On("DecryptConfig", mock.Anything, mock.Anything).Return(nil)

	result, err := (API{}).UpdateOutput(mockUpdateOutputInput)

	assert.NoError(t, err)
	assert.Equal(t, aws.String("outputId"), result.OutputID)
	assert.Equal(t, aws.String("displayName"), result.DisplayName)
	assert.Equal(t, aws.String("createdBy"), result.CreatedBy)
	assert.Equal(t, aws.String("userId"), result.LastModifiedBy)
	assert.Equal(t, aws.String("sns"), result.OutputType)

	mockOutputsTable.AssertExpectations(t)
}

func TestUpdateOutputOtherItemExists(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable

	preExistingAlertItem := &models.AlertOutputItem{
		OutputID: aws.String("outputId-2"),
	}

	mockOutputsTable.On("GetOutputByName", aws.String("displayName")).Return(preExistingAlertItem, nil)

	result, err := (API{}).UpdateOutput(mockUpdateOutputInput)

	assert.Error(t, err)
	assert.Nil(t, result)
	mockOutputsTable.AssertExpectations(t)
}

func TestUpdateSameOutpuOutput(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey
	mockDefaultsTable := &mockDefaultsTable{}
	defaultsTable = mockDefaultsTable

	alertOutputItem := &models.AlertOutputItem{
		OutputID:           aws.String("outputId"),
		DisplayName:        aws.String("displayName"),
		CreatedBy:          aws.String("createdBy"),
		CreationTime:       aws.String("createdTime"),
		OutputType:         aws.String("sns"),
		VerificationStatus: aws.String(models.VerificationStatusSuccess),
		EncryptedConfig:    make([]byte, 1),
	}

	preExistingAlertItem := &models.AlertOutputItem{
		OutputID: mockUpdateOutputInput.OutputID,
	}

	mockDefaultsTable.On("GetDefaults", mock.Anything).Return([]*models.DefaultOutputsItem{}, nil)
	mockDefaultsTable.On("GetDefault", mock.Anything).Return(&models.DefaultOutputsItem{}, nil)
	mockDefaultsTable.On("PutDefaults", mock.Anything).Return(nil)
	mockOutputsTable.On("UpdateOutput", mock.Anything).Return(alertOutputItem, nil)
	mockOutputsTable.On("GetOutputByName", aws.String("displayName")).Return(preExistingAlertItem, nil)
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)
	mockEncryptionKey.On("DecryptConfig", mock.Anything, mock.Anything).Return(nil)

	result, err := (API{}).UpdateOutput(mockUpdateOutputInput)

	assert.NoError(t, err)
	assert.Equal(t, aws.String("outputId"), result.OutputID)
	assert.Equal(t, aws.String("displayName"), result.DisplayName)
	assert.Equal(t, aws.String("createdBy"), result.CreatedBy)
	assert.Equal(t, aws.String("userId"), result.LastModifiedBy)
	assert.Equal(t, aws.String("sns"), result.OutputType)
	assert.Equal(t, aws.String(models.VerificationStatusSuccess), result.VerificationStatus)

	mockOutputsTable.AssertExpectations(t)
}

func TestUpdateOutputAddSeverity(t *testing.T) {
	// The output was configured to have only CRITICAL severity.
	// Update configures it be be for CRITICAL and HIGH severity
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey
	mockDefaultsTable := &mockDefaultsTable{}
	defaultsTable = mockDefaultsTable

	// Output was default for CRITICAL severity
	previousDefaults := []*models.DefaultOutputsItem{
		{
			Severity:  aws.String("CRITICAL"),
			OutputIDs: []*string{alertOutputItem.OutputID},
		},
	}
	mockDefaultsTable.On("GetDefaults", mock.Anything).Return(previousDefaults, nil)

	// First the output will be removed from CRITICAL
	expectedRemoveDefaultOutputForCritical := &models.DefaultOutputsItem{
		Severity:  aws.String("CRITICAL"),
		OutputIDs: []*string{},
	}
	mockDefaultsTable.On("PutDefaults", expectedRemoveDefaultOutputForCritical).Return(nil).Once()

	// We expect that the output will be added as default for CRITICAL and HIGH
	expectedAddDefaultOutputForCritical := &models.DefaultOutputsItem{
		Severity:  aws.String("CRITICAL"),
		OutputIDs: []*string{alertOutputItem.OutputID},
	}
	expectedAddDefaultOutputForHigh := &models.DefaultOutputsItem{
		Severity:  aws.String("HIGH"),
		OutputIDs: []*string{alertOutputItem.OutputID},
	}
	mockDefaultsTable.On("PutDefaults", expectedAddDefaultOutputForCritical).Return(nil).Once()
	mockDefaultsTable.On("PutDefaults", expectedAddDefaultOutputForHigh).Return(nil).Once()

	mockOutputsTable.On("GetOutputByName", aws.String("displayName")).Return(alertOutputItem, nil)
	mockDefaultsTable.On("GetDefault", mock.Anything).Return(nil, nil)
	mockOutputsTable.On("UpdateOutput", mock.Anything).Return(alertOutputItem, nil)
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)
	mockEncryptionKey.On("DecryptConfig", mock.Anything, mock.Anything).Return(nil)

	updateOutputInput := &models.UpdateOutputInput{
		OutputID:           alertOutputItem.OutputID,
		DisplayName:        alertOutputItem.DisplayName,
		UserID:             alertOutputItem.LastModifiedBy,
		OutputConfig:       &models.OutputConfig{Sns: &models.SnsConfig{}},
		DefaultForSeverity: aws.StringSlice([]string{"CRITICAL", "HIGH"}),
	}
	result, err := (API{}).UpdateOutput(updateOutputInput)

	assert.NoError(t, err)
	assert.Equal(t, updateOutputInput.OutputID, result.OutputID)
	assert.Equal(t, updateOutputInput.DisplayName, result.DisplayName)
	assert.Equal(t, updateOutputInput.UserID, result.LastModifiedBy)
	assert.Equal(t, aws.String("sns"), result.OutputType)

	mockOutputsTable.AssertExpectations(t)
}

func TestUpdateOutputRemoveSeverity(t *testing.T) {
	// The output was configured to have only CRITICAL and HIGH severity.
	// Update configures it be be only for CRITICAL severity
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable
	mockEncryptionKey := &mockEncryptionKey{}
	encryptionKey = mockEncryptionKey
	mockDefaultsTable := &mockDefaultsTable{}
	defaultsTable = mockDefaultsTable

	// Output was default for CRITICAL and HIGH severity
	previousDefaults := []*models.DefaultOutputsItem{
		{
			Severity:  aws.String("CRITICAL"),
			OutputIDs: []*string{alertOutputItem.OutputID},
		},
		{
			Severity:  aws.String("HIGH"),
			OutputIDs: []*string{alertOutputItem.OutputID},
		},
	}
	mockDefaultsTable.On("GetDefaults", mock.Anything).Return(previousDefaults, nil)

	// First the output will be removed from CRITICAL and HIGH
	expectedRemoveDefaultOutputForCritical := &models.DefaultOutputsItem{
		Severity:  aws.String("CRITICAL"),
		OutputIDs: []*string{},
	}
	expectedRemoveDefaultOutputForHigh := &models.DefaultOutputsItem{
		Severity:  aws.String("HIGH"),
		OutputIDs: []*string{},
	}
	mockDefaultsTable.On("PutDefaults", expectedRemoveDefaultOutputForCritical).Return(nil).Once()
	mockDefaultsTable.On("PutDefaults", expectedRemoveDefaultOutputForHigh).Return(nil).Once()

	// We expect that the output will be added as default for CRITICAL and HIGH
	expectedAddDefaultOutputForCritical := &models.DefaultOutputsItem{
		Severity:  aws.String("CRITICAL"),
		OutputIDs: []*string{alertOutputItem.OutputID},
	}
	mockDefaultsTable.On("PutDefaults", expectedAddDefaultOutputForCritical).Return(nil).Once()

	mockOutputsTable.On("GetOutputByName", aws.String("displayName")).Return(alertOutputItem, nil)
	mockDefaultsTable.On("GetDefault", mock.Anything).Return(nil, nil)
	mockOutputsTable.On("UpdateOutput", mock.Anything).Return(alertOutputItem, nil)
	mockEncryptionKey.On("EncryptConfig", mock.Anything).Return(make([]byte, 1), nil)
	mockEncryptionKey.On("DecryptConfig", mock.Anything, mock.Anything).Return(nil)

	updateOutputInput := &models.UpdateOutputInput{
		OutputID:           alertOutputItem.OutputID,
		DisplayName:        alertOutputItem.DisplayName,
		UserID:             alertOutputItem.LastModifiedBy,
		OutputConfig:       &models.OutputConfig{Sns: &models.SnsConfig{}},
		DefaultForSeverity: aws.StringSlice([]string{"CRITICAL"}),
	}
	result, err := (API{}).UpdateOutput(updateOutputInput)

	assert.NoError(t, err)
	assert.Equal(t, updateOutputInput.OutputID, result.OutputID)
	assert.Equal(t, updateOutputInput.DisplayName, result.DisplayName)
	assert.Equal(t, updateOutputInput.UserID, result.LastModifiedBy)
	assert.Equal(t, aws.String("sns"), result.OutputType)

	mockOutputsTable.AssertExpectations(t)
}
