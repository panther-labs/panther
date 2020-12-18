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

	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	rulemodels "github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/internal/log_analysis/alert_forwarder/forwarder"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
	"github.com/panther-labs/panther/pkg/testutils"
)

type AlertAPITest struct {
	API

	mockTable     *tableMock
	mockRuleCache *ruleCacheMock
	mockS3        *testutils.S3Mock
}

func (a *AlertAPITest) AssertExpectations(t *testing.T) {
	a.mockS3.AssertExpectations(t)
	a.mockRuleCache.AssertExpectations(t)
	a.mockTable.AssertExpectations(t)
}

type ruleCacheMock struct {
	forwarder.RuleCache
	mock.Mock
}

func (r *ruleCacheMock) Get(id, version string) (*rulemodels.Rule, error) {
	args := r.Called(id, version)
	return args.Get(0).(*rulemodels.Rule), args.Error(1)
}

type tableMock struct {
	table.API
	mock.Mock
}

func (m *tableMock) GetAlert(input string) (*table.AlertItem, error) {
	args := m.Called(input)
	return args.Get(0).(*table.AlertItem), args.Error(1)
}

func (m *tableMock) ListAll(input *models.ListAlertsInput) ([]*table.AlertItem, *string, error) {
	args := m.Called(input)
	return args.Get(0).([]*table.AlertItem), args.Get(1).(*string), args.Error(2)
}

func (m *tableMock) UpdateAlertStatus(input *models.UpdateAlertStatusInput) ([]*table.AlertItem, error) {
	args := m.Called(input)
	return args.Get(0).([]*table.AlertItem), args.Error(1)
}

func (m *tableMock) UpdateAlertDelivery(input *models.UpdateAlertDeliveryInput) (*table.AlertItem, error) {
	args := m.Called(input)
	return args.Get(0).(*table.AlertItem), args.Error(1)
}

func initTestAPI() *AlertAPITest {
	mockTable := &tableMock{}
	mockS3 := &testutils.S3Mock{}
	mockRuleCache := &ruleCacheMock{}

	api := API{
		alertsDB:  mockTable,
		s3Client:  mockS3,
		ruleCache: mockRuleCache,
		env: envConfig{
			ProcessedDataBucket: "bucket",
		},
	}

	return &AlertAPITest{
		mockRuleCache: mockRuleCache,
		mockS3:        mockS3,
		mockTable:     mockTable,
		API:           api,
	}
}
