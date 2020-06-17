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
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/internal/core/outputs_api/table"
	"github.com/panther-labs/panther/pkg/encryption"
)

type mockOutputTable struct {
	table.OutputsTable
	mock.Mock
}

func (m *mockOutputTable) GetOutput(outputID *string) (*table.AlertOutputItem, error) {
	args := m.Called(outputID)
	return args.Get(0).(*table.AlertOutputItem), args.Error(1)
}

func (m *mockOutputTable) DeleteOutput(outputID *string) error {
	args := m.Called(outputID)
	return args.Error(0)
}

func (m *mockOutputTable) GetOutputs() ([]*table.AlertOutputItem, error) {
	args := m.Called()
	return args.Get(0).([]*table.AlertOutputItem), args.Error(1)
}

func (m *mockOutputTable) UpdateOutput(input *table.AlertOutputItem) (*table.AlertOutputItem, error) {
	args := m.Called(input)
	return args.Get(0).(*table.AlertOutputItem), args.Error(1)
}

func (m *mockOutputTable) GetOutputByName(displayName *string) (*table.AlertOutputItem, error) {
	args := m.Called(displayName)
	alertOutputItem := args.Get(0)
	if alertOutputItem == nil {
		return nil, args.Error(1)
	}
	return alertOutputItem.(*table.AlertOutputItem), args.Error(1)
}

func (m *mockOutputTable) PutOutput(output *table.AlertOutputItem) error {
	args := m.Called(output)
	return args.Error(0)
}

type mockEncryptionKey struct {
	encryption.Key
	mock.Mock
}

func (m *mockEncryptionKey) DecryptConfig(ciphertext []byte, config interface{}) error {
	args := m.Called(ciphertext, config)
	plaintext := []byte(`{"slack": {"webhookURL": "https://hooks.slack.com/services/bb/aa/11"}}`)
	_ = jsoniter.Unmarshal(plaintext, config)
	return args.Error(0)
}

func (m *mockEncryptionKey) EncryptConfig(config interface{}) ([]byte, error) {
	args := m.Called(config)
	return args.Get(0).([]byte), args.Error(1)
}
