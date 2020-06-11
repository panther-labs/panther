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

func (tb GlueTableTimebin) Validate() (err error) {
	switch tb {
	case GlueTableHourly, GlueTableDaily, GlueTableMonthly:
		return
	default:
		err = fmt.Errorf("unknown GlueTableMetadata table time bin: %d", tb)
	}
	return
}

// Next returns the next time interval
func (tb GlueTableTimebin) Next(t time.Time) (next time.Time) {
	switch tb {
	case GlueTableHourly:
		return t.Add(time.Hour).Truncate(time.Hour)
	case GlueTableDaily:
		return t.Add(time.Hour * 24).Truncate(time.Hour * 24)
	case GlueTableMonthly:
		// loop a day at a time until the month changes
		currentMonth := t.Month()
		for next = t.Add(time.Hour * 24).Truncate(time.Hour * 24); next.Month() == currentMonth; next = next.Add(time.Hour * 24) {
		}
		return next
	default:
		panic(fmt.Sprintf("unknown GlueTableMetadata table time bin: %d", tb))
	}
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
	}
	return
}

// PartitionS3PathFromTime constructs the S3 path for this partition
func (tb GlueTableTimebin) PartitionS3PathFromTime(t time.Time) (s3Path string) {
	switch tb {
	case GlueTableHourly:
		return fmt.Sprintf("year=%d/month=%02d/day=%02d/hour=%02d/", t.Year(), t.Month(), t.Day(), t.Hour())
	case GlueTableDaily:
		return fmt.Sprintf("year=%d/month=%02d/day=%02d/", t.Year(), t.Month(), t.Day())
	default:
		return fmt.Sprintf("year=%d/month=%02d/", t.Year(), t.Month())
	}
}

// PartitionHasData checks if there is at least 1 s3 object in the partition
func (tb GlueTableTimebin) PartitionHasData(client s3iface.S3API, t time.Time, tableOutput *glue.GetTableOutput) (bool, error) {
	bucket, prefix, err := ParseS3URL(*tableOutput.Table.StorageDescriptor.Location)
	if err != nil {
		return false, errors.Wrapf(err, "Cannot parse s3 path: %s",
			*tableOutput.Table.StorageDescriptor.Location)
	}

	// list files w/pagination
	inputParams := &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		Prefix:  aws.String(prefix + tb.PartitionS3PathFromTime(t)),
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
