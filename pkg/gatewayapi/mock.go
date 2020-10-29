package gatewayapi

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
)

type MockClient struct {
	API
	mock.Mock
}

func (m *MockClient) Invoke(input, output interface{}) (int, error) {
	args := m.Called(input, output)

	// The third "return value" of the mock is used to set the output
	body, err := jsoniter.Marshal(args.Get(2))
	if err != nil {
		panic(err)
	}
	if output != nil {
		if err := jsoniter.Unmarshal(body, output); err != nil {
			panic(err)
		}
	}

	return args.Int(0), args.Error(1)
}
