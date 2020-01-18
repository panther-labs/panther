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

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

var mockGetOrganizationOutputsInput = &models.GetOrganizationOutputsInput{}

var alertOutputItem = &models.AlertOutputItem{
	OutputID:           aws.String("outputId"),
	DisplayName:        aws.String("displayName"),
	CreatedBy:          aws.String("createdBy"),
	CreationTime:       aws.String("creationTime"),
	LastModifiedBy:     aws.String("lastModifiedBy"),
	LastModifiedTime:   aws.String("lastModifiedTime"),
	OutputType:         aws.String("slack"),
	VerificationStatus: aws.String(models.VerificationStatusSuccess),
	EncryptedConfig:    make([]byte, 1),
}

func TestGetOrganizationOutputs(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable
	mockEncryptionKey := new(mockEncryptionKey)
	encryptionKey = mockEncryptionKey
	mockOutputVerification := &mockOutputVerification{}
	outputVerification = mockOutputVerification
	mockDefaultsTable := &mockDefaultsTable{}
	defaultsTable = mockDefaultsTable

	mockOutputsTable.On("GetOutputs").Return([]*models.AlertOutputItem{alertOutputItem}, nil)
	mockEncryptionKey.On("DecryptConfig", make([]byte, 1), mock.Anything).Return(nil)
	mockDefaultsTable.On("GetDefaults", mock.Anything).Return([]*models.DefaultOutputsItem{}, nil)

	expectedAlertOutput := &models.AlertOutput{
		OutputID:           aws.String("outputId"),
		OutputType:         aws.String("slack"),
		CreatedBy:          aws.String("createdBy"),
		CreationTime:       aws.String("creationTime"),
		DisplayName:        aws.String("displayName"),
		LastModifiedBy:     aws.String("lastModifiedBy"),
		LastModifiedTime:   aws.String("lastModifiedTime"),
		VerificationStatus: aws.String(models.VerificationStatusSuccess),
		OutputConfig:       &models.OutputConfig{},
		DefaultForSeverity: []*string{},
	}

	result, err := (API{}).GetOrganizationOutputs(mockGetOrganizationOutputsInput)

	assert.NoError(t, err)
	assert.Equal(t, []*models.AlertOutput{expectedAlertOutput}, result)
	mockOutputsTable.AssertExpectations(t)
	mockEncryptionKey.AssertExpectations(t)
	mockDefaultsTable.AssertExpectations(t)
}

func TestGetOrganizationOutputsDdbError(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable

	mockOutputsTable.On("GetOutputs").Return([]*models.AlertOutputItem{}, errors.New("fake error"))

	_, err := (API{}).GetOrganizationOutputs(mockGetOrganizationOutputsInput)

	assert.Error(t, errors.New("fake error"), err)
	mockOutputsTable.AssertExpectations(t)
}

func TestGetOrganizationDecryptionError(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable
	mockEncryptionKey := new(mockEncryptionKey)
	encryptionKey = mockEncryptionKey

	mockOutputsTable.On("GetOutputs").Return([]*models.AlertOutputItem{alertOutputItem}, nil)
	mockEncryptionKey.On("DecryptConfig", make([]byte, 1), mock.Anything).Return(errors.New("fake error"))

	_, err := (API{}).GetOrganizationOutputs(mockGetOrganizationOutputsInput)

	assert.Error(t, errors.New("fake error"), err)
	mockOutputsTable.AssertExpectations(t)
	mockEncryptionKey.AssertExpectations(t)
}
