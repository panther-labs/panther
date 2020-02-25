package awsglue

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
)

const (
	LogS3Prefix       = "logs"
	RuleMatchS3Prefix = "rules"

	LogProcessingDatabaseName        = "panther_logs"
	LogProcessingDatabaseDescription = "Holds tables with data from Panther log processing"

	RuleMatchDatabaseName        = "panther_rule_matches"
	RuleMatchDatabaseDescription = "Holds tables with data from Panther rule matching (same table structure as panther_logs)"

	ViewsDatabaseName        = "panther_views"
	ViewsDatabaseDescription = "Holds views useful for querying Panther data"

	GlueTimestampType = "timestamp" // type in Glue tables for timestamps that we will re-map Go times
)

// Use this to tag the time partitioning used in a Glue table
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
		err = fmt.Errorf("unknown Glue table time bin: %d", tb)
	}
	return
}

// return the next time interval
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
		panic(fmt.Sprintf("unknown Glue table time bin: %d", tb))
	}
}

// Meta data about Glue table over parser data written to S3
// NOTE: this struct has all accessor behind functions to allow a lazy evaluation
//       so the cost of creating the schema is only when actually needing this information.
type GlueMetadata struct {
	databaseName string
	tableName    string
	description  string
	s3Prefix     string           // where we expect to find data relative to the bucket (excluding time partitions)
	timebin      GlueTableTimebin // at what time resolution is this table partitioned
	timeUnpadded bool             // if true, do not zero pad partition time values
	eventStruct  interface{}      // object used to infer columns
}

func (gm *GlueMetadata) DatabaseName() string {
	return gm.databaseName
}

func (gm *GlueMetadata) TableName() string {
	return gm.tableName
}

func (gm *GlueMetadata) Description() string {
	return gm.description
}

func (gm *GlueMetadata) S3Prefix() string {
	return gm.s3Prefix
}

func (gm *GlueMetadata) Timebin() GlueTableTimebin {
	return gm.timebin
}

// Based on Timebin(), return an S3 prefix for objects
func (gm *GlueMetadata) PartitionPrefix(t time.Time) (prefix string) {
	partitionValues := gm.PartitionValues(t)
	prefix = gm.s3Prefix
	switch gm.timebin {
	case GlueTableHourly:
		prefix += fmt.Sprintf("year=%s/month=%s/day=%s/hour=%s/",
			*partitionValues[0], *partitionValues[1], *partitionValues[2], *partitionValues[3])
	case GlueTableDaily:
		prefix += fmt.Sprintf("year=%s/month=%s/day=%s/",
			*partitionValues[0], *partitionValues[1], *partitionValues[2])
	case GlueTableMonthly:
		prefix += fmt.Sprintf("year=%s/month=%s/",
			*partitionValues[0], *partitionValues[1])
	}
	return
}

type Partition struct {
	Name string
	Type string
}

func (gm *GlueMetadata) PartitionKeys() (partitions []Partition) {
	partitions = []Partition{
		{Name: "year", Type: "int"},
	}

	if gm.Timebin() >= GlueTableMonthly {
		partitions = append(partitions, Partition{Name: "month", Type: "int"})
	}
	if gm.Timebin() >= GlueTableDaily {
		partitions = append(partitions, Partition{Name: "day", Type: "int"})
	}
	if gm.Timebin() >= GlueTableHourly {
		partitions = append(partitions, Partition{Name: "hour", Type: "int"})
	}
	return partitions
}

// Based on Timebin(), return an []*string values (used for Glue APIs)
func (gm *GlueMetadata) PartitionValues(t time.Time) (values []*string) {
	var intFormat string

	if gm.timeUnpadded {
		intFormat = "%d"
	} else {
		intFormat = "%02d"
	}

	values = []*string{aws.String(fmt.Sprintf("%d", t.Year()))} // always unpadded

	if gm.timebin >= GlueTableMonthly {
		values = append(values, aws.String(fmt.Sprintf(intFormat, t.Month())))
	}
	if gm.timebin >= GlueTableDaily {
		values = append(values, aws.String(fmt.Sprintf(intFormat, t.Day())))
	}
	if gm.timebin >= GlueTableHourly {
		values = append(values, aws.String(fmt.Sprintf(intFormat, t.Hour())))
	}
	return
}

func (gm *GlueMetadata) EventStruct() interface{} {
	return gm.eventStruct
}

// Clone returns a copy of table with s3Prefix and database changed
func (gm *GlueMetadata) Clone(s3Prefix, databaseName string) *GlueMetadata {
	clone := *gm // copy
	clone.s3Prefix = standardizeS3Prefix(s3Prefix, gm.TableName())
	clone.databaseName = databaseName
	return &clone
}

func NewGlueMetadata(s3Prefix, databaseName, tableName, description string, timebin GlueTableTimebin,
	timeUnpadded bool, eventStruct interface{}) (gm *GlueMetadata, err error) {

	err = timebin.Validate()
	if err != nil {
		return
	}

	// clean table name to make sql friendly
	tableName = strings.Replace(tableName, ".", "_", -1) // no '.'
	tableName = strings.ToLower(tableName)

	gm = &GlueMetadata{
		databaseName: databaseName,
		tableName:    tableName,
		description:  description,
		s3Prefix:     standardizeS3Prefix(s3Prefix, tableName),
		timebin:      timebin,
		timeUnpadded: timeUnpadded,
		eventStruct:  eventStruct,
	}

	return
}

func standardizeS3Prefix(s3Prefix, tableName string) string {
	return s3Prefix + "/" + tableName + "/" // ensure last char is '/'
}
