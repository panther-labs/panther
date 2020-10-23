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
	maxSeriesDataPoints  = 100800
	maxMetricsPerRequest = 500
)

var (
	metricsInternalError = &genericapi.InternalError{Message: "Failed to generate requested metrics. Please try again later"}
	metricResolvers      = map[string]func(input *models.GetMetricsInput, output *models.GetMetricsOutput) error{
		"alertsByRuleID":   getAlertsByRuleID,
		"alertsBySeverity": getAlertsBySeverity,
		"eventsLatency":    getEventsLatency,
		"eventsProcessed":  getEventsProcessed,
		"totalAlertsDelta": getTotalAlertsDelta,
	}
)

// GetMetrics routes the requests for various metric data to the correct handlers
func (API) GetMetrics(input *models.GetMetricsInput) (*models.GetMetricsOutput, error) {
	// Round the timestamps to align with CloudWatch's rounding
	var minInterval int64
	input.FromDate, input.ToDate, minInterval = roundInterval(input.FromDate, input.ToDate)
	if minInterval > input.IntervalMinutes {
		input.IntervalMinutes = minInterval
	}

	response := &models.GetMetricsOutput{
		FromDate:        input.FromDate,
		ToDate:          input.ToDate,
		IntervalMinutes: input.IntervalMinutes,
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
	delta := input.ToDate.Sub(input.FromDate)
	intervals := int(math.Ceil(delta.Minutes() / float64(input.IntervalMinutes)))
	times := make([]*time.Time, intervals)
	for i := 1; i <= intervals; i++ {
		times[intervals-i] = aws.Time(input.FromDate.Add(time.Minute * time.Duration(input.IntervalMinutes) * time.Duration(i-1)))
	}
	zap.L().Debug("times calculated",
		zap.Int("intervals", intervals),
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
		//
		// times is calculated based the IntervalMinutes and FromDate parameter set in the
		// request. These same parameters are sent to CloudWatch, which uses them to calculate the
		// timestamps for the values. So the times that we create should match exactly the times
		// that CloudWatch returns, except for cases where CloudWatch omits a timestamp for
		// having no values in the time period. For those cases, we insert a 0.
		fullValues := make([]*float64, len(times))
		for j, k := 0, 0; j < len(times); j++ {
			if k < len(metricData.Values) && *times[j] == *metricData.Timestamps[k] {
				fullValues[j] = metricData.Values[k]
				k++
			} else {
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

// roundInterval determines the correct starting time and minimum interval for a metric
// based on the following rules set by CloudWatch:
//
// Start time less than 15 days ago - Round down to the nearest whole minute.
// Data points with a period of 60 seconds (1 minute) are available for 15 days.
//   - Example: 12:32:34 is rounded down to 12:32:00, with a minimum interval of 1 minute.
// Start time between 15 and 63 days ago - Round down to the nearest 5-minute clock interval.
// Data points with a period of 300 seconds (5 minute) are available for 63 days.
//   - Example, 12:32:34 is rounded down to 12:30:00, with a minimum interval of 5 minutes.
// Start time greater than 63 days ago - Round down to the nearest 1-hour clock interval.
// Data points with a period of 3600 seconds (1 hour) are available for 455 days (15 months).
//   - Example, 12:32:34 is rounded down to 12:00:00 with a minimum interval of 1 hour.
//
// References:
// https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricData.html
// https://aws.amazon.com/cloudwatch/faqs/
//
// Additionally, we round the endDate as well. This is important otherwise the final period will
// be only a few seconds or minutes long, which can give misleading results.
func roundInterval(startDate, endDate time.Time) (time.Time, time.Time, int64) {
	now := time.Now()
	if now.Sub(startDate) < 15*24*time.Hour {
		// Round to the nearest minute by truncating all seconds and nanoseconds.
		return roundToUTCMinute(startDate), roundToUTCMinute(endDate), 1
	}
	if now.Sub(startDate) < 63*24*time.Hour {
		// Round to the nearest 5 minute interval by truncating the number of minutes past the
		// nearest 5 minute interval in addition to any seconds, and nanoseconds.
		return roundToUTCMinute(startDate).Truncate(5 * time.Minute), roundToUTCMinute(endDate).Truncate(5 * time.Minute), 5
	}
	// Round to the nearest hour by truncating all minutes, seconds, and nanoseconds.
	return roundToUTCMinute(startDate).Truncate(60 * time.Minute), roundToUTCMinute(endDate).Truncate(60 * time.Minute), 60
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
	samples := int64(duration.Minutes()) / input.IntervalMinutes
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
		zap.L().Info("no metrics returned for query", zap.Any("queries", queries))
	}

	return responses, nil
}
