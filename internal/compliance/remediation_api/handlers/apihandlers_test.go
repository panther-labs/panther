package handlers

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
	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/remediation/models"
	"github.com/panther-labs/panther/internal/compliance/remediation_api/remediation"
)

type mockInvoker struct {
	remediation.InvokerAPI
	mock.Mock
}

func (m *mockInvoker) Remediate(input *models.RemediateResourceInput) error {
	args := m.Called(input)
	return args.Error(0)
}

func (m *mockInvoker) GetRemediations() (*models.ListRemediationsOutput, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ListRemediationsOutput), args.Error(1)
}
