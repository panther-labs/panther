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
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/metrics/models"
	"github.com/panther-labs/panther/pkg/genericapi"
	"github.com/panther-labs/panther/pkg/metrics"
)

const (
	// These limits are enforced by AWS
	maxSeriesDataPoints   = 100800
	maxMetricsPerRequest  = 500
	eventsProcessedMetric = "EventsProcessed"
)

var (
	metricsInternalError = &genericapi.InternalError{Message: "Failed to generate requested metrics. Please try again later"}
	metricResolvers      = map[string]func(input *models.GetMetricsInput) (*models.MetricResult, error){
		"eventsProcessed": getEventsProcessed,
	}
)

// GetMetrics builds a routes the requests for various metric data to the correct handlers
func (API) GetMetrics(input *models.GetMetricsInput) (*models.GetMetricsOutput, error) {
	zap.L().Debug("beginning metric generation")
	response := &models.GetMetricsOutput{
		MetricResults: make([]models.MetricResult, len(input.MetricNames)),
		FromDate:      input.FromDate,
		ToDate:        input.ToDate,
		IntervalHours: input.IntervalHours,
	}
	for i, metricName := range input.MetricNames {
		resolver, ok := metricResolvers[metricName]
		if !ok {
			return nil, &genericapi.InvalidInputError{Message: "unexpected metric [" + metricName + "] requested"}
		}
		metricData, err := resolver(input)
		if err != nil {
			return nil, err
		}
		response.MetricResults[i] = *metricData
	}

	return response, nil
}

// getEventsProcessed returns the count of events processed by the log processor per log type
//
// This is a time series metric.
func getEventsProcessed(input *models.GetMetricsInput) (*models.MetricResult, error) {
	// First determine applicable metric dimensions
	var listMetricsResponse []*cloudwatch.Metric
	err := cloudwatchClient.ListMetricsPages(&cloudwatch.ListMetricsInput{
		MetricName: aws.String(eventsProcessedMetric),
		Namespace:  aws.String(metrics.Namespace),
	}, func(page *cloudwatch.ListMetricsOutput, keepPaging bool) bool {
		listMetricsResponse = append(listMetricsResponse, page.Metrics...)
		return true
	})
	if err != nil {
		zap.L().Error("unable to list metrics", zap.String("metric", eventsProcessedMetric))
		return nil, metricsInternalError
	}
	zap.L().Debug("found applicable metrics", zap.Any("metrics", listMetricsResponse))

	// Build the query based on the applicable metric dimensions
	queries := make([]*cloudwatch.MetricDataQuery, len(listMetricsResponse))
	for i, metric := range listMetricsResponse {
		queries[i] = &cloudwatch.MetricDataQuery{
			Id: aws.String("query" + strconv.Itoa(i)),
			MetricStat: &cloudwatch.MetricStat{
				Metric: metric,
				Period: aws.Int64(input.IntervalHours * 3600), // number of seconds, must be multiple of 60
				Stat:   aws.String("Sum"),
				Unit:   aws.String("Count"),
			},
			ReturnData: aws.Bool(true), // whether to return data or just calculate results for other expressions to use
		}
	}
	zap.L().Debug("prepared metric queries", zap.Any("queries", queries), zap.Any("toDate", input.ToDate), zap.Any("fromDate", input.FromDate))

	metricData, err := getMetricData(input, queries)

	if err != nil {
		zap.L().Error("unable to query metric data", zap.Any("queries", queries), zap.Error(err))
		return nil, metricsInternalError
	}

	results := make([]models.TimeSeriesResponse, len(metricData))
	for i, metricData := range metricData {
		results[i] = models.TimeSeriesResponse{
			Label:      metricData.Label,
			Timestamps: metricData.Timestamps,
			Values:     metricData.Values,
		}
	}

	return &models.MetricResult{
		MetricName: eventsProcessedMetric,
		SeriesData: results,
	}, nil
}

// getMetricData handles generic batching & validation while making GetMetricData API calls
func getMetricData(input *models.GetMetricsInput, queries []*cloudwatch.MetricDataQuery) ([]*cloudwatch.MetricDataResult, error) {
	queryCount := len(queries)

	// Validate that we can fit this request in our maximum data point threshold
	duration := input.ToDate.Sub(input.FromDate)
	samples := int64(duration.Hours()) / input.IntervalHours
	metricsPerCall := queryCount
	if metricsPerCall > maxMetricsPerRequest {
		metricsPerCall = maxMetricsPerRequest
	}
	if samples*int64(metricsPerCall) > maxSeriesDataPoints {
		return nil, &genericapi.InvalidInputError{Message: "too many data points requested please narrow query scope"}
	}

	responses := make([]*cloudwatch.MetricDataResult, 0, queryCount)
	for start := 0; start < queryCount; start += maxMetricsPerRequest {
		end := start + maxMetricsPerRequest
		if end > queryCount {
			end = queryCount
		}
		err := cloudwatchClient.GetMetricDataPages(&cloudwatch.GetMetricDataInput{
			EndTime:           aws.Time(input.ToDate),
			MaxDatapoints:     aws.Int64(maxSeriesDataPoints),
			MetricDataQueries: queries[start:end],
			StartTime:         aws.Time(input.FromDate),
		}, func(page *cloudwatch.GetMetricDataOutput, _ bool) bool {
			responses = append(responses, page.MetricDataResults...)
			return true
		})
		if err != nil {
			return nil, err
		}
	}

	return responses, nil
}
