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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	deliverymodel "github.com/panther-labs/panther/api/lambda/delivery/models"
	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/internal/core/outputs_api/table"
)

var mockInput = &models.GetOutputsInput{}

var alertOutputItem = &table.AlertOutputItem{
	OutputID:           aws.String("outputId"),
	DisplayName:        aws.String("displayName"),
	CreatedBy:          aws.String("createdBy"),
	CreationTime:       aws.String("creationTime"),
	LastModifiedBy:     aws.String("lastModifiedBy"),
	LastModifiedTime:   aws.String("lastModifiedTime"),
	OutputType:         aws.String("slack"),
	EncryptedConfig:    make([]byte, 1),
	DefaultForSeverity: aws.StringSlice([]string{"HIGH"}),
}

func TestGetOutputs(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable
	mockEncryptionKey := new(mockEncryptionKey)
	encryptionKey = mockEncryptionKey

	mockOutputsTable.On("GetOutputs").Return([]*table.AlertOutputItem{alertOutputItem}, nil)
	mockEncryptionKey.On("DecryptConfig", make([]byte, 1), mock.Anything).Return(nil)

	expectedAlertOutput := &models.AlertOutput{
		OutputID:           aws.String("outputId"),
		OutputType:         aws.String("slack"),
		CreatedBy:          aws.String("createdBy"),
		CreationTime:       aws.String("creationTime"),
		DisplayName:        aws.String("displayName"),
		LastModifiedBy:     aws.String("lastModifiedBy"),
		LastModifiedTime:   aws.String("lastModifiedTime"),
		OutputConfig:       &models.OutputConfig{Slack: &models.SlackConfig{WebhookURL: redacted}},
		DefaultForSeverity: aws.StringSlice([]string{"HIGH"}),
		AlertTypes:         []string{deliverymodel.RuleType, deliverymodel.RuleErrorType, deliverymodel.PolicyType},
	}

	result, err := (API{}).GetOutputs(mockInput)

	assert.NoError(t, err)
	assert.Equal(t, []*models.AlertOutput{expectedAlertOutput}, result)
	mockOutputsTable.AssertExpectations(t)
	mockEncryptionKey.AssertExpectations(t)
}

func TestGetOrganizationOutputsDdbError(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable

	mockOutputsTable.On("GetOutputs").Return([]*table.AlertOutputItem{}, errors.New("fake error"))

	_, err := (API{}).GetOutputs(mockInput)

	assert.Error(t, errors.New("fake error"), err)
	mockOutputsTable.AssertExpectations(t)
}

func TestGetOrganizationDecryptionError(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable
	mockEncryptionKey := new(mockEncryptionKey)
	encryptionKey = mockEncryptionKey

	mockOutputsTable.On("GetOutputs").Return([]*table.AlertOutputItem{alertOutputItem}, nil)
	mockEncryptionKey.On("DecryptConfig", make([]byte, 1), mock.Anything).Return(errors.New("fake error"))

	_, err := (API{}).GetOutputs(mockInput)

	assert.Error(t, errors.New("fake error"), err)
	mockOutputsTable.AssertExpectations(t)
	mockEncryptionKey.AssertExpectations(t)
}
