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
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/metrics/models"
)

const (
	maxSeriesDataPoints   = 100000
	logProcessorNamespace = "panther/log_processor"
	bytesProcessedMetric  = "bytesProcessed"
)

var (
	metricResolvers = map[string]func(input *models.GetMetricsInput) (*models.MetricResult, error){
		"bytesProcessed": getBytesProcessed,
	}
)

// GetMetrics adds a set of new integrations in a batch.
func (API) GetMetrics(input *models.GetMetricsInput) (*models.GetMetricsOutput, error) {
	zap.L().Debug("beginning metric generation")
	response := &models.GetMetricsOutput{
		MetricResults: make(map[string]*models.MetricResult, len(input.MetricNames)),
		FromDate:      input.FromDate,
		ToDate:        input.ToDate,
		Period:        input.Period,
	}
	for _, metricName := range input.MetricNames {
		resolver, ok := metricResolvers[metricName]
		if !ok {
			return nil, errors.New("unexpected metric [" + metricName + "] requested")
		}
		metricData, err := resolver(input)
		if err != nil {
			return nil, err
		}
		response.MetricResults[metricName] = metricData
	}

	return response, nil
}

func getBytesProcessed(input *models.GetMetricsInput) (*models.MetricResult, error) {
	// First determine applicable metric dimensions
	metrics, err := cloudwatchClient.ListMetrics(&cloudwatch.ListMetricsInput{
		MetricName: aws.String(bytesProcessedMetric),
		Namespace:  aws.String(logProcessorNamespace),
	})
	if err != nil {
		return nil, err
	}

	// Validate that we can this request in our maximum data point threshold
	duration := input.ToDate.Sub(input.FromDate)
	samples := int64(duration.Hours()) / input.Period
	if samples*int64(len(metrics.Metrics)) > maxSeriesDataPoints {
		return nil, errors.New("too many data points requested please narrow query scope")
	}

	// Build the query based on the applicable metric dimensions
	//
	// This will fail if there are more than 100 log types. If we get to the point where we expect
	// users will have over 100 log types, this will have to be batched then merged.
	queries := make([]*cloudwatch.MetricDataQuery, 0, 12)
	for i, metric := range metrics.Metrics {
		queries = append(queries, &cloudwatch.MetricDataQuery{
			Id: aws.String("query" + strconv.Itoa(i)),
			MetricStat: &cloudwatch.MetricStat{
				Metric: metric,
				Period: aws.Int64(input.Period * 3600), // number of seconds, must be multiple of 60
				Stat:   aws.String("Sum"),
				Unit:   aws.String("Bytes"),
			},
			ReturnData: aws.Bool(true), // whether to return data or just calculate results for other expressions to use
		})
	}

	response, err := cloudwatchClient.GetMetricData(&cloudwatch.GetMetricDataInput{
		EndTime:           aws.Time(input.ToDate),
		MaxDatapoints:     aws.Int64(maxSeriesDataPoints),
		MetricDataQueries: queries,
		NextToken:         nil,
		ScanBy:            nil,
		StartTime:         aws.Time(input.FromDate),
	})

	if err != nil {
		return nil, err
	}

	results := make(map[string]*models.TimeSeriesResponse, len(response.MetricDataResults))
	for _, metricData := range response.MetricDataResults {
		results[aws.StringValue(metricData.Id)] = &models.TimeSeriesResponse{
			Timestamps: metricData.Timestamps,
			Values:     metricData.Values,
		}
	}

	return &models.MetricResult{
		SeriesData: results,
	}, nil
}
