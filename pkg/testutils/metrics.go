package testutils

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
	"context"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/panther-labs/panther/pkg/metrics"
)

type LoggerMock struct {
	metrics.Logger
	mock.Mock
}

func (m *LoggerMock) Log(dimensions []metrics.Dimension, metrics ...metrics.Metric) {
	m.Called(dimensions, metrics)
}

type CounterMock struct {
	metrics.Counter
	mock.Mock
}

func (m *CounterMock) With(dimensionValues ...string) metrics.Counter {
	args := m.Called(dimensionValues)
	return args.Get(0).(metrics.Counter)
}
func (m *CounterMock) Add(delta float64) {
	m.Called(delta)
}

type MetricsManagerMock struct {
	metrics.Manager
	mock.Mock
}

func (m *MetricsManagerMock) Run(ctx context.Context, interval time.Duration) {
	m.Called(ctx, interval)
}
func (m *MetricsManagerMock) NewCounter(name, unit string) metrics.Counter {
	args := m.Called(name, unit)
	return args.Get(0).(metrics.Counter)
}

func (m *MetricsManagerMock) Sync() error {
	return m.Called().Error(0)
}
