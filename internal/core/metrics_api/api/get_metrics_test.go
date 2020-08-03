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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/metrics/models"
)

func TestRoundToUTCMinute(t *testing.T) {
	initialTime, err := time.Parse(time.RFC3339Nano, "2020-01-03T05:07:47.999999999+07:00")
	require.NoError(t, err)

	roundedTime := roundToUTCMinute(initialTime)

	// These fields should not  change
	assert.Equal(t, initialTime.Year(), roundedTime.Year())
	assert.Equal(t, initialTime.Month(), roundedTime.Month())
	assert.Equal(t, initialTime.Minute(), roundedTime.Minute())

	// These fields should be adjusted due to UTC conversion
	assert.NotEqual(t, initialTime.Day(), roundedTime.Day())
	assert.Equal(t, initialTime.UTC().Day(), roundedTime.Day())
	assert.NotEqual(t, initialTime.Hour(), roundedTime.Hour())
	assert.Equal(t, initialTime.UTC().Hour(), roundedTime.Hour())
	assert.Equal(t, time.UTC, roundedTime.Location())

	// These fields should have been truncated
	assert.Equal(t, 0, roundedTime.Second())
	assert.Equal(t, 0, roundedTime.Nanosecond())
}

func TestGetPeriodStartAndInterval(t *testing.T) {
	now := roundToUTCMinute(time.Now())

	// Offset by a few hours, seconds, and nanoseconds. This should be rounded to the nearest minute.
	minuteStartTime := now.Add(-8*time.Hour + 32*time.Second + 640*time.Nanosecond)
	minuteEndTime := minuteStartTime.Add(4 * time.Hour)
	minuteStart, minuteEnd, minuteInterval := roundInterval(minuteStartTime, minuteEndTime)

	assert.Equal(t, int64(1), minuteInterval)
	// These fields should not  change
	assert.Equal(t, minuteStartTime.Year(), minuteStart.Year())
	assert.Equal(t, minuteStartTime.Month(), minuteStart.Month())
	assert.Equal(t, minuteStartTime.Day(), minuteStart.Day())
	assert.Equal(t, minuteStartTime.Hour(), minuteStart.Hour())
	assert.Equal(t, minuteStartTime.Minute(), minuteStart.Minute())
	assert.Equal(t, minuteEndTime.Year(), minuteEnd.Year())
	assert.Equal(t, minuteEndTime.Month(), minuteEnd.Month())
	assert.Equal(t, minuteEndTime.Day(), minuteEnd.Day())
	assert.Equal(t, minuteEndTime.Hour(), minuteEnd.Hour())
	assert.Equal(t, minuteEndTime.Minute(), minuteEnd.Minute())
	// These fields should have been truncated
	assert.Equal(t, 0, minuteStart.Second())
	assert.Equal(t, 0, minuteStart.Nanosecond())
	assert.Equal(t, 0, minuteEnd.Second())
	assert.Equal(t, 0, minuteEnd.Nanosecond())

	// Offset by 30 days to get into the next time bucket, then add some minutes, seconds, and nanoseconds.
	// This should be rounded to the nearest five minute interval.
	fiveMinuteStartTime := now.Add((-30 * 24 * time.Hour) + 52*time.Second + 777*time.Nanosecond)
	// Remove all minutes, so  we can explicitly set the minute field
	fiveMinuteStartTime = fiveMinuteStartTime.Truncate(60 * time.Minute).Add(7 * time.Minute)
	fiveMinuteEndTime := fiveMinuteStartTime.Add(4 * time.Hour)
	fiveMinuteStart, fiveMinuteEnd, fiveMinuteInterval := roundInterval(fiveMinuteStartTime, fiveMinuteEndTime)
	assert.Equal(t, int64(5), fiveMinuteInterval)
	// These fields should not  change
	assert.Equal(t, fiveMinuteStartTime.Year(), fiveMinuteStart.Year())
	assert.Equal(t, fiveMinuteStartTime.Month(), fiveMinuteStart.Month())
	assert.Equal(t, fiveMinuteStartTime.Day(), fiveMinuteStart.Day())
	assert.Equal(t, fiveMinuteStartTime.Hour(), fiveMinuteStart.Hour())
	assert.Equal(t, fiveMinuteEndTime.Year(), fiveMinuteEnd.Year())
	assert.Equal(t, fiveMinuteEndTime.Month(), fiveMinuteEnd.Month())
	assert.Equal(t, fiveMinuteEndTime.Day(), fiveMinuteEnd.Day())
	assert.Equal(t, fiveMinuteEndTime.Hour(), fiveMinuteEnd.Hour())
	// These fields should have been truncated
	assert.NotEqual(t, fiveMinuteStartTime.Minute(), fiveMinuteStart.Minute())
	assert.NotEqual(t, fiveMinuteEndTime.Minute(), fiveMinuteEnd.Minute())
	assert.Equal(t, 5, fiveMinuteStart.Minute())
	assert.Equal(t, 0, fiveMinuteStart.Second())
	assert.Equal(t, 0, fiveMinuteStart.Nanosecond())
	assert.Equal(t, 5, fiveMinuteEnd.Minute())
	assert.Equal(t, 0, fiveMinuteEnd.Second())
	assert.Equal(t, 0, fiveMinuteEnd.Nanosecond())

	// Offset by 90 days to get into the next time bucket, then add some minutes, seconds, and nanoseconds.
	// This should be rounded to the nearest hour.
	hourStartTime := now.Add((-90 * 24 * time.Hour) + 52*time.Second + 777*time.Nanosecond + 3*time.Hour)
	hourEndTime := hourStartTime.Add(8 * time.Hour)
	hourStart, hourEnd, hourInterval := roundInterval(hourStartTime, hourEndTime)
	assert.Equal(t, int64(60), hourInterval)
	// These fields should not  change
	assert.Equal(t, hourStartTime.Year(), hourStart.Year())
	assert.Equal(t, hourStartTime.Month(), hourStart.Month())
	assert.Equal(t, hourStartTime.Day(), hourStart.Day())
	assert.Equal(t, hourStartTime.Hour(), hourStart.Hour())
	assert.Equal(t, hourEndTime.Year(), hourEnd.Year())
	assert.Equal(t, hourEndTime.Month(), hourEnd.Month())
	assert.Equal(t, hourEndTime.Day(), hourEnd.Day())
	assert.Equal(t, hourEndTime.Hour(), hourEnd.Hour())
	// These fields should have been truncated
	assert.Equal(t, 0, hourStart.Minute())
	assert.Equal(t, 0, hourStart.Second())
	assert.Equal(t, 0, hourStart.Nanosecond())
	assert.Equal(t, 0, hourEnd.Minute())
	assert.Equal(t, 0, hourEnd.Second())
	assert.Equal(t, 0, hourEnd.Nanosecond())
}

func TestNormalizeTimestamps(t *testing.T) {
	// Because the timestamp bucketing relies on the difference from the current time, we start with
	// today's date then set the hours, minutes, etc. accordingly to produce the time range we care
	// about.
	today := roundToUTCMinute(time.Now()).Truncate(24 * time.Hour).Truncate(60 * time.Minute)

	// These two times are offset by slightly more than 4 hours. Therefore with a 1 hour interval, we
	// expect five values per metric.
	//
	// Since the fromDate is within the last 15 days, the from and to dates will be rounded to the
	// nearest minute already by this stage.
	fromDate := today.Add(4 * time.Hour).Add(33 * time.Minute)
	toDate := today.Add(8 * time.Hour).Add(55 * time.Minute)

	input := &models.GetMetricsInput{
		FromDate:        fromDate,
		ToDate:          toDate,
		IntervalMinutes: 60,
	}

	data := []*cloudwatch.MetricDataResult{
		// This metric has no gaps in the time frame. Its values should stay the same.
		{
			Label: aws.String("label1"),
			Timestamps: []*time.Time{
				aws.Time(fromDate.Add(4 * time.Hour)),
				aws.Time(fromDate.Add(3 * time.Hour)),
				aws.Time(fromDate.Add(2 * time.Hour)),
				aws.Time(fromDate.Add(1 * time.Hour)),
				aws.Time(fromDate),
			},
			Values: []*float64{
				aws.Float64(100),
				aws.Float64(94),
				aws.Float64(104),
				aws.Float64(87),
				aws.Float64(22),
			},
		},
		// This metric has a few gaps in the time frame. Those gaps should be filled with zeros.
		{
			Label: aws.String("label2"),
			Timestamps: []*time.Time{
				aws.Time(fromDate.Add(4 * time.Hour)),
				aws.Time(fromDate.Add(2 * time.Hour)),
				aws.Time(fromDate),
			},
			Values: []*float64{
				aws.Float64(20),
				aws.Float64(16),
				aws.Float64(7),
			},
		},
		// This metric has no results in the time frame. It should be filled with zeros.
		{
			Label: aws.String("label2"),
		},
	}

	values, timestamps := normalizeTimeStamps(input, data)

	// Three metrics should be returned
	require.Len(t, values, 3)
	// Five intervals should be returned
	assert.Len(t, timestamps, 5)

	// Each metric should now have five values, regardless of how many they started with
	require.Len(t, values[0].Values, 5)
	require.Len(t, values[1].Values, 5)
	require.Len(t, values[2].Values, 5)

	// The first metric is not missing any values, so it should remain unchanged
	firstMetric := values[0]
	assert.Equal(t, *data[0].Label, *firstMetric.Label)
	assert.Equal(t, data[0].Values, firstMetric.Values)

	// The second metric is missing two values, so those values should be filled with zeros
	secondMetric := values[1]
	assert.Equal(t, *data[1].Label, *secondMetric.Label)
	assert.Equal(t, *data[1].Values[0], *secondMetric.Values[0])
	assert.Equal(t, float64(0), *secondMetric.Values[1])
	assert.Equal(t, *data[1].Values[1], *secondMetric.Values[2])
	assert.Equal(t, float64(0), *secondMetric.Values[3])
	assert.Equal(t, *data[1].Values[2], *secondMetric.Values[4])

	// The third metric is missing all values, so those values should be filled with zeros
	thirdMetric := values[2]
	assert.Equal(t, *thirdMetric.Label, *data[2].Label)
	for _, metricValue := range thirdMetric.Values {
		assert.Equal(t, float64(0), *metricValue)
	}
}
