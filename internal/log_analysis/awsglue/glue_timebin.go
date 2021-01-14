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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/pkg/errors"
)

// Use this to tag the time partitioning used in a GlueTableMetadata table
type GlueTableTimebin int

const (
	GlueTableMonthly GlueTableTimebin = iota + 1
	GlueTableDaily
	GlueTableHourly
)

// Truncate truncates the date to the time bin time unit
func (tb GlueTableTimebin) Truncate(t time.Time) time.Time {
	switch tb {
	case GlueTableHourly:
		return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location())
	case GlueTableDaily:
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	case GlueTableMonthly:
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
	default:
		panic(fmt.Sprintf("unknown GlueTableMetadata table time bin: %d", tb))
	}
}

// Next returns the next time interval
func (tb GlueTableTimebin) Next(t time.Time) (next time.Time) {
	switch tb {
	case GlueTableHourly:
		return time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
	case GlueTableDaily:
		return time.Date(t.Year(), t.Month(), t.Day()+1, t.Hour(), 0, 0, 0, t.Location())
	case GlueTableMonthly:
		return time.Date(t.Year(), t.Month()+1, t.Day(), t.Hour(), 0, 0, 0, t.Location())
	default:
		panic(fmt.Sprintf("unknown GlueTableMetadata table time bin: %d", tb))
	}
}

// PartitionsBefore returns an expression to scan for partitions before tm
// see https://docs.aws.amazon.com/glue/latest/webapi/API_GetPartitions.html
// nolint:lll
func (tb GlueTableTimebin) PartitionsBefore(tm time.Time) string {
	tm = tb.Truncate(tm.UTC())
	var values []string
	values = append(values, fmt.Sprintf("(year < %d)", tm.Year()))
	if tb >= GlueTableMonthly {
		values = append(values, fmt.Sprintf("(year = %d AND month < %02d)", tm.Year(), tm.Month()))
	}
	if tb >= GlueTableDaily {
		values = append(values, fmt.Sprintf("(year = %d AND month = %02d AND day < %02d)", tm.Year(), tm.Month(), tm.Day()))
	}
	if tb >= GlueTableHourly {
		values = append(values, fmt.Sprintf("(year = %d AND month = %02d AND day = %02d AND hour < %02d)", tm.Year(), tm.Month(), tm.Day(), tm.Hour()))
	}
	return strings.Join(values, " OR ")
}

// PartitionFilter returns a partition filter expression
func (tb GlueTableTimebin) PartitionFilter(start, end time.Time) string {
	if start.IsZero() && end.IsZero() {
		return ""
	}
	if start.IsZero() {
		return tb.PartitionsBefore(end.UTC())
	}
	if end.IsZero() {
		return tb.PartitionsAfter(start.UTC())
	}
	return tb.PartitionsBetween(start.UTC(), end.UTC())
}

// PartitionsAfter returns an expression to scan for partitions after tm
// see https://docs.aws.amazon.com/glue/latest/webapi/API_GetPartitions.html
// nolint:lll
func (tb GlueTableTimebin) PartitionsAfter(tm time.Time) string {
	tm = tb.Truncate(tm.UTC())
	var values []string
	values = append(values, fmt.Sprintf("(year > %d)", tm.Year()))
	if tb >= GlueTableMonthly {
		values = append(values, fmt.Sprintf("(year = %d AND month > %02d)", tm.Year(), tm.Month()))
	}
	if tb >= GlueTableDaily {
		values = append(values, fmt.Sprintf("(year = %d AND month = %02d AND day > %02d)", tm.Year(), tm.Month(), tm.Day()))
	}
	if tb >= GlueTableHourly {
		values = append(values, fmt.Sprintf("(year = %d AND month = %02d AND day = %02d AND hour > %02d)", tm.Year(), tm.Month(), tm.Day(), tm.Hour()))
	}
	return strings.Join(values, " OR ")
}

// PartitionsBetween returns an expression to scan for partitions between two timestamps
// see https://docs.aws.amazon.com/glue/latest/webapi/API_GetPartitions.html
func (tb GlueTableTimebin) PartitionsBetween(start, end time.Time) string {
	before := tb.PartitionsBefore(end)
	after := tb.PartitionsAfter(start)
	return fmt.Sprintf("(%s) AND (%s)", before, after)
}

// PartitionValuesFromTime returns an []*string values (used for Glue APIs)
func (tb GlueTableTimebin) PartitionValuesFromTime(t time.Time) (values []*string) {
	values = []*string{aws.String(fmt.Sprintf("%d", t.Year()))}

	if tb >= GlueTableMonthly {
		values = append(values, aws.String(fmt.Sprintf("%02d", t.Month())))
	}
	if tb >= GlueTableDaily {
		values = append(values, aws.String(fmt.Sprintf("%02d", t.Day())))
	}
	if tb >= GlueTableHourly {
		values = append(values, aws.String(fmt.Sprintf("%02d", t.Hour())))
		values = append(values, aws.String(fmt.Sprintf("%10d", t.Truncate(time.Hour).Unix())))
	}
	return
}

// TimebinFromTable resolves the timebin from a table storage descriptor
func TimebinFromTable(tbl *glue.TableData) (GlueTableTimebin, error) {
	keyNames := columnNames(tbl.PartitionKeys)
	switch len(keyNames) {
	case 2:
		if keyNames[0] == "year" && keyNames[1] == "month" {
			return GlueTableMonthly, nil
		}
	case 3:
		if keyNames[0] == "year" && keyNames[1] == "month" && keyNames[2] == "day" {
			return GlueTableDaily, nil
		}
	case 4, 5:
		if keyNames[0] == "year" && keyNames[1] == "month" && keyNames[2] == "day" && keyNames[3] == "hour" {
			return GlueTableHourly, nil
		}
	}
	return 0, errors.Errorf("cannot determine the table time bin %s [%s]", aws.StringValue(tbl.Name), strings.Join(keyNames, ", "))
}

// columnNames is a helper to extract just the column names from a list of columns
func columnNames(cols []*glue.Column) []string {
	if cols == nil {
		return nil
	}
	names := make([]string, len(cols))
	for i := range cols {
		names[i] = aws.StringValue(cols[i].Name)
	}
	return names
}

// PartitionPathS3 constructs the S3 path for this partition
func (tb GlueTableTimebin) PartitionPathS3(t time.Time) (s3Path string) {
	switch tb {
	case GlueTableHourly:
		return fmt.Sprintf("year=%d/month=%02d/day=%02d/hour=%02d/", t.Year(), t.Month(), t.Day(), t.Hour())
	case GlueTableDaily:
		return fmt.Sprintf("year=%d/month=%02d/day=%02d/", t.Year(), t.Month(), t.Day())
	case GlueTableMonthly:
		return fmt.Sprintf("year=%d/month=%02d/", t.Year(), t.Month())
	default:
		return ""
	}
}

// TimeFromS3Path converts an S3 path to time.
// The path must not contain any prefixes such as db/table name
func (tb GlueTableTimebin) TimeFromS3Path(path string) (time.Time, bool) {
	// Trim leading slash
	if len(path) > 0 && path[0] == '/' {
		path = path[1:]
	}
	if layout := tb.S3PathLayout(); layout != "" && len(path) >= len(layout) {
		tm, err := time.Parse(layout, path[:len(layout)])
		if err == nil {
			return tm, true
		}
	}
	return time.Time{}, false
}

// S3PathLayout returns a go time layout to format/parse S3 paths for Glue partitions
func (tb GlueTableTimebin) S3PathLayout() string {
	switch tb {
	case GlueTableHourly:
		return "year=2006/month=01/day=02/hour=15/"
	case GlueTableDaily:
		return "year=2006/month=01/day=02/"
	case GlueTableMonthly:
		return "year=2006/month=01/"
	default:
		return ""
	}
}

// PartitionHasData checks if there is at least 1 S3 object in the partition
func (tb GlueTableTimebin) PartitionHasData(client s3iface.S3API, t time.Time, tableOutput *glue.GetTableOutput) (bool, error) {
	bucket, prefix, err := ParseS3URL(*tableOutput.Table.StorageDescriptor.Location)
	if err != nil {
		return false, errors.Wrapf(err, "Cannot parse s3 path: %s",
			*tableOutput.Table.StorageDescriptor.Location)
	}

	// list files w/pagination
	inputParams := &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		Prefix:  aws.String(prefix + tb.PartitionPathS3(t)),
		MaxKeys: aws.Int64(1), // look for at least 1
	}
	var hasData bool
	err = client.ListObjectsV2Pages(inputParams, func(page *s3.ListObjectsV2Output, isLast bool) bool {
		for _, value := range page.Contents {
			if *value.Size > 0 { // we only care about objects with size
				hasData = true
			}
		}
		return !hasData // "To stop iterating, return false from the fn function."
	})

	return hasData, err
}

// PartitionTimeFromValues resolves the timebin from a glue partition's values
func PartitionTimeFromValues(values []*string) (tm time.Time, err error) {
	switch len(values) {
	case 2:
		tm = unpackValues(values[0], values[1], nil, nil)
	case 3:
		tm = unpackValues(values[0], values[1], values[2], nil)
	case 4, 5:
		tm = unpackValues(values[0], values[1], values[2], values[3])
	}
	if tm.IsZero() {
		return time.Time{}, errors.Errorf("invalid partition values [%s]", strings.Join(aws.StringValueSlice(values), ", "))
	}
	return tm, nil
}

func unpackValues(y, m, d, h *string) (tm time.Time) {
	var (
		year  int
		month = 1
		day   = 1
		hour  = 0
		err   error
	)
	if y != nil {
		if year, err = strconv.Atoi(*y); err != nil {
			return
		}
	}
	if m != nil {
		if month, err = strconv.Atoi(*m); err != nil {
			return
		}
	}
	if d != nil {
		if day, err = strconv.Atoi(*d); err != nil {
			return
		}
	}
	if h != nil {
		if hour, err = strconv.Atoi(*h); err != nil {
			return
		}
	}
	return time.Date(year, time.Month(month), day, hour, 0, 0, 0, time.UTC)
}
