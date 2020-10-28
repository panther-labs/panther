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
	MetricNames     []string  `json:"metricNames" validate:"required"`
	Namespace       string    `json:"namespace"`
	FromDate        time.Time `json:"fromDate" validate:"required"`
	ToDate          time.Time `json:"toDate" validate:"required,gtfield=FromDate"`
	IntervalMinutes int64     `json:"intervalMinutes" validate:"required,gt=0"`
}

// GetMetricsOutput contains data points for a number of metrics over the specified time frame
type GetMetricsOutput struct {
	EventsProcessed  *MetricResult `json:"eventsProcessed,omitempty"`
	EventsLatency    *MetricResult `json:"eventsLatency,omitempty"`
	TotalAlertsDelta *MetricResult `json:"totalAlertsDelta,omitempty"`
	AlertsBySeverity *MetricResult `json:"alertsBySeverity,omitempty"`
	AlertsByRuleID   *MetricResult `json:"alertsByRuleID,omitempty"`
	FromDate         time.Time     `json:"fromDate"`
	ToDate           time.Time     `json:"toDate"`
	IntervalMinutes  int64         `json:"intervalMinutes"`
}

// MetricResult is either a single data point or a series of timestamped data points
type MetricResult = struct {
	SingleValue []SingleMetric   `json:"singleValue"`
	SeriesData  TimeSeriesMetric `json:"seriesData"`
}

type SingleMetric struct {
	Label *string  `json:"label"`
	Value *float64 `json:"value"`
}

// TimeSeriesResponse contains the pertinent fields from the GetMetricData response to be passed
// back to the frontend
type TimeSeriesMetric struct {
	Timestamps []*time.Time       `json:"timestamps"`
	Series     []TimeSeriesValues `json:"series"`
}

type TimeSeriesValues struct {
	Label  *string    `json:"label"`
	Values []*float64 `json:"values"`
}
