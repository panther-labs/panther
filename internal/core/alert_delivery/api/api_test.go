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

// MockAPI is a mocked object that implements the API interface
// It describes an object that the apis rely on.
// type MockAPI struct {
// 	API
// 	mock.Mock
// }

// type MockTable struct {
// 	table.API
// 	mock.Mock
// }

// func (m *MockAPI) DeliverAlert(input *models.DeliverAlertInput) (*models.DeliverAlertOutput, error) {
// 	args := m.Called(input)
// 	return args.Get(0).(*models.DeliverAlertOutput), args.Error(1)
// }
