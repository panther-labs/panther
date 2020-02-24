package outputs

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

import "github.com/stretchr/testify/mock"

func init() {
	policyURLPrefix = "https://panther.io/policies/"
	alertURLPrefix = "https://panther.io/alerts/"
}

type mockHTTPWrapper struct {
	HTTPWrapper
	mock.Mock
}

func (m *mockHTTPWrapper) post(postInput *PostInput) *AlertDeliveryError {
	args := m.Called(postInput)
	return args.Get(0).(*AlertDeliveryError)
}
