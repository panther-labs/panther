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
)

// getEventsProcessed returns the count of events processed by the log processor per log type
//
// This is a time series metric.
func getEventsProcessed(input *models.GetMetricsInput, output *models.GetMetricsOutput) error {
	// First determine applicable metric dimensions
	var listMetricsResponse []*cloudwatch.Metric
	err := cloudwatchClient.ListMetricsPages(&cloudwatch.ListMetricsInput{
		MetricName: aws.String(eventsProcessedMetric),
		Namespace:  aws.String(input.Namespace),
	}, func(page *cloudwatch.ListMetricsOutput, _ bool) bool {
		listMetricsResponse = append(listMetricsResponse, page.Metrics...)
		return true
	})
	if err != nil {
		zap.L().Error("unable to list metrics", zap.String("metric", eventsProcessedMetric))
		return metricsInternalError
	}
	zap.L().Debug("found applicable metrics", zap.Any("metrics", listMetricsResponse))

	// Build the query based on the applicable metric dimensions
	queries := make([]*cloudwatch.MetricDataQuery, len(listMetricsResponse))
	for i, metric := range listMetricsResponse {
		queries[i] = &cloudwatch.MetricDataQuery{
			Id: aws.String("query" + strconv.Itoa(i)),
			MetricStat: &cloudwatch.MetricStat{
				Metric: metric,
				Period: aws.Int64(input.IntervalMinutes * 60), // number of seconds, must be multiple of 60
				Stat:   aws.String("Sum"),
				Unit:   aws.String("Count"),
			},
		}
	}
	zap.L().Debug("prepared metric queries", zap.Any("queries", queries), zap.Any("toDate", input.ToDate), zap.Any("fromDate", input.FromDate))

	metricData, err := getMetricData(input, queries)
	if err != nil {
		return err
	}

	values, timestamps := normalizeTimeStamps(input, metricData)

	output.EventsProcessed = &models.MetricResult{
		SeriesData: models.TimeSeriesMetric{
			Timestamps: timestamps,
			Series:     values,
		},
	}
	return nil
}
