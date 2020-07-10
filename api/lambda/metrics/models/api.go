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

// GetMetricsInput is used to request data points for a number of metrics over a given time frame
type GetMetricsInput struct {
	MetricNames   []string  `json:"metricNames" validate:"required"`
	FromDate      time.Time `json:"fromDate" validate:"required"`
	ToDate        time.Time `json:"toDate" validate:"required,gtfield=FromDate"`
	IntervalHours int64     `json:"intervalHours" validate:"required,gt=0"`
}

// GetMetricsOutput contains data points for a number of metrics over the specified time frame
type GetMetricsOutput struct {
	MetricResults []MetricResult `json:"metricNames" validate:"required"`
	FromDate      time.Time      `json:"fromDate"`
	ToDate        time.Time      `json:"toDate"`
	IntervalHours int64          `json:"intervalHours"`
}

// MetricResult is either a single data point or a series of timestamped data points
type MetricResult = struct {
	MetricName  string
	SingleValue []SingleMetricValue  `json:"singleValue,omitempty"`
	SeriesData  []TimeSeriesResponse `json:"seriesData,omitempty"`
}

type SingleMetricValue struct {
	Label *string
	Value int64
}

// TimeSeriesResponse contains the pertinent fields from the GetMetricData response to be passed
// back to the frontend
type TimeSeriesResponse struct {
	Label      *string
	Timestamps []*time.Time
	Values     []*float64
}
