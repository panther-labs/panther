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
	"math"
	"time"

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
	alertsMetric          = "AlertsCreated"
)

var (
	metricsInternalError = &genericapi.InternalError{Message: "Failed to generate requested metrics. Please try again later"}
	metricsNoDataError   = &genericapi.DoesNotExistError{
		Message: "Could not find data points for the given metric in the selected time period"}
	metricResolvers = map[string]func(input *models.GetMetricsInput, output *models.GetMetricsOutput) error{
		"eventsProcessed":  getEventsProcessed,
		"alertsBySeverity": getAlertsBySeverity,
		"totalAlertsDelta": getTotalAlertsDelta,
	}
)

// GetMetrics routes the requests for various metric data to the correct handlers
func (API) GetMetrics(input *models.GetMetricsInput) (*models.GetMetricsOutput, error) {
	response := &models.GetMetricsOutput{
		FromDate:      input.FromDate,
		ToDate:        input.ToDate,
		IntervalHours: input.IntervalHours,
	}

	// If a namespace was not specified, default to the Panther namespace
	if input.Namespace == "" {
		input.Namespace = metrics.Namespace
	}

	for _, metricName := range input.MetricNames {
		resolver, ok := metricResolvers[metricName]
		if !ok {
			return nil, &genericapi.InvalidInputError{Message: "unexpected metric [" + metricName + "] requested"}
		}
		err := resolver(input, response)
		if err != nil {
			return nil, err
		}
	}

	return response, nil
}

// normalizeTimeStamps takes a GetMetricsInput and a list of metric values and determines based off
// the GetMetricsInput how many values should be present, then fills in any missing values with 0
// values. This function should be called for ALL time series metrics.
//
// This is necessary because CloudWatch will simply omit any value for intervals where no metrics
// were generated, but most other services which will be consuming these metrics interpret a missing
// data point as missing, not a zero value. So for a metric that was queried across three time
// intervals t1, t2, and  t3 but for which there was no activity in  t2, CloudWatch will return
// [t1, t3], [v1, v3]. This will be graphed as a straight line from v1 to v3, when in reality it
// should go from v1 to 0 then back up to v3.
func normalizeTimeStamps(input *models.GetMetricsInput, data []*cloudwatch.MetricDataResult) ([]models.TimeSeriesValues, []*time.Time) {
	// First we need to calculate the expected timestamps, so we know if any are missing
	tStart := getTruncatedStart(input.FromDate)
	delta := input.ToDate.Sub(tStart)
	intervals := int(math.Ceil(delta.Hours() / float64(input.IntervalHours)))
	times := make([]*time.Time, intervals)
	for i := 1; i <= intervals; i++ {
		times[intervals-i] = aws.Time(tStart.Add(time.Hour * time.Duration(input.IntervalHours) * time.Duration(i-1)))
	}
	zap.L().Debug("times calculated",
		zap.Int("intervals", intervals),
		zap.Time("tStart", tStart),
		zap.Any("delta", delta),
		zap.Any("times", times),
	)

	// Now that we know what times should be present, we fill in any missing spots with 0 values
	values := make([]models.TimeSeriesValues, len(data))
	for i, metricData := range data {
		// In most cases there is activity in each interval, in which case the rest of the logic is
		// not necessary. Simply take the provided values and continue.
		if len(times) == len(metricData.Timestamps) {
			zap.L().Debug("full metric times present, no fills needed")
			values[i] = models.TimeSeriesValues{
				Label:  metricData.Label,
				Values: metricData.Values,
			}
			continue
		}

		// In some cases, an interval will have no value. AWS just omits these intervals from the
		// results, but most systems will not implicitly understand an omitted interval to mean zero
		// activity, so we fill in a zero value.
		fullValues := make([]*float64, len(times))
		for j, k := 0, 0; j < len(times); j++ {
			// If the k'th value occurred during the j'th time, keep it and increment k.
			if k < len(metricData.Values) && *times[j] == *metricData.Timestamps[k] {
				fullValues[j] = metricData.Values[k]
				k++
			} else {
				// Otherwise, insert a zero.
				fullValues[j] = aws.Float64(0)
			}
		}
		values[i] = models.TimeSeriesValues{
			Label:  metricData.Label,
			Values: fullValues,
		}
	}

	return values, times
}

// getTruncatedStart determines the correct starting time for a metric based on the following
// rules set by CloudWatch:
// Start time less than 15 days ago - Round down to the nearest whole minute.
//   - Example: 12:32:34 is rounded down to 12:32:00.
// Start time between 15 and 63 days ago - Round down to the nearest 5-minute clock interval.
//   - Example, 12:32:34 is rounded down to 12:30:00.
// Start time greater than 63 days ago - Round down to the nearest 1-hour clock interval.
//   - Example, 12:32:34 is rounded down to 12:00:00.
//
// Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricData.html
func getTruncatedStart(startDate time.Time) time.Time {
	now := time.Now()
	if now.Sub(startDate) < 15*24*time.Hour {
		// Round to the nearest minute by truncating all seconds and nanoseconds
		return roundToUTCMinute(startDate)
	}
	if now.Sub(startDate) < 63*24*time.Hour {
		// Round to the nearest 5 minute interval by truncating the number of minutes past the
		// nearest 5 minute interval in addition to any seconds, and nanoseconds
		return roundToUTCMinute(startDate).Truncate(5 * time.Minute)
	}
	// Round to the nearest hour by truncating all minutes, seconds, and nanoseconds
	return roundToUTCMinute(startDate).Truncate(60 * time.Minute)
}

// roundToUTCMinute returns the given time in UTC, rounded down to the nearest minute
func roundToUTCMinute(input time.Time) time.Time {
	// Truncate up to 60 seconds (the maximum number of seconds in a minute) and 1,000,000,000
	// nanoseconds, the maximum number of nanoseconds in a second.
	return input.UTC().Truncate(60 * time.Second).Truncate(1000000000 * time.Nanosecond)
}

// getMetricData handles generic batching & validation while making GetMetricData API calls
func getMetricData(input *models.GetMetricsInput, queries []*cloudwatch.MetricDataQuery) ([]*cloudwatch.MetricDataResult, error) {
	// Validate that we can fit this request in our maximum data point threshold
	queryCount := len(queries)
	duration := input.ToDate.Sub(input.FromDate)
	samples := int64(duration.Hours()) / input.IntervalHours
	metricsPerCall := queryCount
	if metricsPerCall > maxMetricsPerRequest {
		metricsPerCall = maxMetricsPerRequest
	}
	if samples*int64(metricsPerCall) > maxSeriesDataPoints {
		// In the future we could consider further batching of the request into groups of
		// maxSeriesDataPoints sized requests. We would have to be careful to not exceed the maximum
		// memory of the lambda, in addition to very carefully selecting the start/stop times for
		// each batch in order to keep the overall time periods correct.
		return nil, &genericapi.InvalidInputError{Message: "too many data points requested please narrow query scope"}
	}

	responses := make([]*cloudwatch.MetricDataResult, 0, queryCount)
	request := &cloudwatch.GetMetricDataInput{
		EndTime:       &input.ToDate,
		MaxDatapoints: aws.Int64(maxSeriesDataPoints),
		StartTime:     &input.FromDate,
	}
	// Batch the requests into groups of requests with no more than maxMetricsPerRequest in each group
	for start := 0; start < queryCount; start += maxMetricsPerRequest {
		end := start + maxMetricsPerRequest
		if end > queryCount {
			end = queryCount
		}
		request.MetricDataQueries = queries[start:end]
		err := cloudwatchClient.GetMetricDataPages(request, func(page *cloudwatch.GetMetricDataOutput, _ bool) bool {
			responses = append(responses, page.MetricDataResults...)
			return true
		})
		if err != nil {
			zap.L().Error("unable to query metric data", zap.Any("queries", queries), zap.Error(err))
			return nil, metricsInternalError
		}
	}

	if len(responses) == 0 {
		zap.L().Warn("no metrics returned for query", zap.Any("queries", queries))
		return nil, metricsNoDataError
	}

	return responses, nil
}
