package api

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
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

var mockDeleteOutputInput = &models.DeleteOutputInput{
	OutputID: aws.String("outputId"),
}

func TestDeleteOutput(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable

	mockOutputsTable.On("DeleteOutput", aws.String("outputId")).Return(nil)

	err := (API{}).DeleteOutput(mockDeleteOutputInput)

	assert.NoError(t, err)
	mockOutputsTable.AssertExpectations(t)
}

func TestDeleteOutputDeleteFails(t *testing.T) {
	mockOutputsTable := &mockOutputTable{}
	outputsTable = mockOutputsTable

	mockOutputsTable.On("DeleteOutput", aws.String("outputId")).Return(errors.New("error"))

	err := (API{}).DeleteOutput(mockDeleteOutputInput)

	require.Error(t, err)
	mockOutputsTable.AssertExpectations(t)
}
