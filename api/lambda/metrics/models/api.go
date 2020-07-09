package models

import "time"

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

// LambdaInput is the collection of all possible args to the Lambda function.
type LambdaInput struct {
	GetMetrics *GetMetricsInput `json:"getMetrics"`
}

//
// GetMetricsInput: Used by the UI to request a series of data points
//

// GetMetricsInput is used to request data points for a number of metrics over a given time frame and periods
type GetMetricsInput struct {
	MetricNames []string  `json:"metricNames" validate:"required"`
	FromDate    time.Time `json:"fromDate" validate:"required"`
	ToDate      time.Time `json:"toDate" validate:"required"`
	Period      int64     `json:"period" validate:"required"`
}

type GetMetricsOutput struct {
	MetricResults map[string]*MetricResult `json:"metricNames" validate:"required"`
	FromDate      time.Time                `json:"fromDate"`
	ToDate        time.Time                `json:"toDate"`
	Period        int64                    `json:"period"`
}

type MetricResult = struct {
	SingleValue *int64                         `json:"singleValue,omitempty"`
	SeriesData  map[string]*TimeSeriesResponse `json:"seriesData"`
}

type TimeSeriesResponse struct {
	Timestamps []*time.Time
	Values     []*float64
}
