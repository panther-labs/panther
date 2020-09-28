package awsglue

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGlueTableTimebinNext(t *testing.T) {
	assert := require.New(t)
	var tb GlueTableTimebin
	refTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	// hour and day are fixed offsets, so only need simple tests

	// test hour ...
	tb = GlueTableHourly
	expectedTime := refTime.Add(time.Hour)
	next := tb.Next(refTime)
	assert.Equal(expectedTime, next, "invalid hourly next")

	// test day ...
	tb = GlueTableDaily
	expectedTime = refTime.Add(time.Hour * 24)
	next = tb.Next(refTime)
	assert.Equal(expectedTime, next, "invalid daily next")

	// test month ... this needs to test crossing year boundaries
	tb = GlueTableMonthly
	// Jan to Feb
	refTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	expectedTime = time.Date(2020, 2, 1, 0, 0, 0, 0, time.UTC)
	next = tb.Next(refTime)
	assert.Equal(expectedTime, next, "invalid monthly next %s %s", expectedTime, next)
	// Dec to Jan, over year boundary
	refTime = time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC)
	expectedTime = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	next = tb.Next(refTime)
	assert.Equal(expectedTime, next)
}

func TestGlueTableTimebinPartitionS3PathFromTime(t *testing.T) {
	var tb GlueTableTimebin
	refTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	// test hour ...
	tb = GlueTableHourly
	expectedPath := "year=2020/month=01/day=01/hour=00/"
	assert.Equal(t, expectedPath, tb.PartitionPathS3(refTime))

	// test day ...
	tb = GlueTableDaily
	expectedPath = "year=2020/month=01/day=01/"
	assert.Equal(t, expectedPath, tb.PartitionPathS3(refTime))

	// test month ... this needs to test crossing year boundaries
	tb = GlueTableMonthly
	expectedPath = "year=2020/month=01/"
	assert.Equal(t, expectedPath, tb.PartitionPathS3(refTime))
}

func TestTimebinTruncate(t *testing.T) {
	assert := require.New(t)
	// hour and day are fixed offsets, so only need simple tests

	// test hourly ...
	{
		tm := time.Date(2020, 1, 1, 0, 23, 0, 0, time.UTC)
		hourly := GlueTableHourly.Truncate(tm)
		expect := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		assert.Equal(expect.Format(time.RFC3339Nano), hourly.Format(time.RFC3339Nano))
	}
	// test daily ...
	{
		tm := time.Date(2020, 1, 1, 23, 23, 0, 0, time.UTC)
		daily := GlueTableDaily.Truncate(tm)
		expect := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		assert.Equal(expect.Format(time.RFC3339Nano), daily.Format(time.RFC3339Nano))
	}
	// test monthly ...
	{
		tm := time.Date(2020, 12, 1, 23, 23, 0, 0, time.UTC)
		monthly := GlueTableMonthly.Truncate(tm)
		expect := time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC)
		assert.Equal(expect.Format(time.RFC3339Nano), monthly.Format(time.RFC3339Nano))
	}
}

func TestTimebinS3PathLayout(t *testing.T) {
	assert := require.New(t)
	// hour and day are fixed offsets, so only need simple tests
	tm := time.Date(2020, 1, 1, 0, 23, 0, 0, time.UTC)
	assert.Equal("year=2020/month=01/day=01/hour=00/", tm.Format(GlueTableHourly.S3PathLayout()))
	assert.Equal("year=2020/month=01/day=01/", tm.Format(GlueTableDaily.S3PathLayout()))
	assert.Equal("year=2020/month=01/", tm.Format(GlueTableMonthly.S3PathLayout()))
	assert.Equal("", GlueTableTimebin(42).S3PathLayout())
}

func TestTimebinTimeFromPath(t *testing.T) {
	assert := require.New(t)
	// hour and day are fixed offsets, so only need simple tests
	{
		expect := time.Date(2020, 1, 1, 23, 0, 0, 0, time.UTC)
		tm, ok := GlueTableHourly.TimeFromS3Path("year=2020/month=01/day=01/hour=23/")
		assert.True(ok)
		assert.Equal(expect.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))
	}
	{
		expect := time.Date(2020, 1, 1, 23, 0, 0, 0, time.UTC)
		tm, ok := GlueTableHourly.TimeFromS3Path("/year=2020/month=01/day=01/hour=23/")
		assert.True(ok)
		assert.Equal(expect.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))
	}
	{
		expect := time.Date(2020, 1, 12, 0, 0, 0, 0, time.UTC)
		tm, ok := GlueTableDaily.TimeFromS3Path("year=2020/month=01/day=12/")
		assert.True(ok)
		assert.Equal(expect.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))
	}
	{
		expect := time.Date(2020, 5, 1, 0, 0, 0, 0, time.UTC)
		tm, ok := GlueTableMonthly.TimeFromS3Path("year=2020/month=05/")
		assert.True(ok)
		assert.Equal(expect.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))
	}
}
func TestTimebinPartitionTime(t *testing.T) {
	assert := require.New(t)
	// hour and day are fixed offsets, so only need simple tests
	{
		expect := time.Date(2020, 1, 1, 23, 0, 0, 0, time.UTC)
		tm, err := PartitionTimeFromValues(aws.StringSlice([]string{"2020", "01", "01", "23"}))
		assert.NoError(err)
		assert.Equal(expect.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))
	}
	{
		expect := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		tm, err := PartitionTimeFromValues(aws.StringSlice([]string{"2020", "01", "01"}))
		assert.NoError(err)
		assert.Equal(expect.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))
	}
	{
		expect := time.Date(2020, 11, 1, 0, 0, 0, 0, time.UTC)
		tm, err := PartitionTimeFromValues(aws.StringSlice([]string{"2020", "11"}))
		assert.NoError(err)
		assert.Equal(expect.Format(time.RFC3339Nano), tm.Format(time.RFC3339Nano))
	}
	{
		_, err := PartitionTimeFromValues(aws.StringSlice([]string{"2020", "foo"}))
		assert.Error(err)
	}
}
