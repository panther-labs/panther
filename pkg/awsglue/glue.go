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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"
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

type PartitionKey struct {
	Name string
	Type string
}

// Meta data about GlueTableMetadata table over parser data written to S3
// NOTE: this struct has all accessor behind functions to allow a lazy evaluation
//       so the cost of creating the schema is only when actually needing this information.
type GlueTableMetadata struct {
	databaseName  string
	tableName     string
	description   string
	logType string
	s3TablePrefix string           // All data for this table are stored in this S3 prefix
	timebin       GlueTableTimebin // at what time resolution is this table partitioned
	timeUnpadded  bool             // if true, do not zero pad partition time values
	eventStruct interface{}
}

func (gm *GlueTableMetadata) DatabaseName() string {
	return gm.databaseName
}

func (gm *GlueTableMetadata) TableName() string {
	return gm.tableName
}

func (gm *GlueTableMetadata) Description() string {
	return gm.description
}

func (gm *GlueTableMetadata) S3Prefix() string {
	return gm.s3TablePrefix
}

func (gm *GlueTableMetadata) Timebin() GlueTableTimebin {
	return gm.timebin
}

func (gm *GlueTableMetadata) Timebin() GlueTableTimebin {
	return gm.timebin
}

func (gm *GlueTableMetadata) EventStruct() interface{} {
	return gm.eventStruct
}

func (gm *GlueTableMetadata) PartitionKeys() (partitions []PartitionKey) {
	partitions = []PartitionKey{
		{Name: "year", Type: "int"},
	}

	if gm.Timebin() >= GlueTableMonthly {
		partitions = append(partitions, PartitionKey{Name: "month", Type: "int"})
	}
	if gm.Timebin() >= GlueTableDaily {
		partitions = append(partitions, PartitionKey{Name: "day", Type: "int"})
	}
	if gm.Timebin() >= GlueTableHourly {
		partitions = append(partitions, PartitionKey{Name: "hour", Type: "int"})
	}
	return partitions
}

// Based on Timebin(), return an S3 prefix for objects
func (gm *GlueTableMetadata) PartitionPrefix(t time.Time) (prefix string) {
	partitionValues := gm.partitionValues(t)
	prefix = gm.s3TablePrefix
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

// Based on Timebin(), return an []*string values (used for GlueTableMetadata APIs)
func (gm *GlueTableMetadata) partitionValues(t time.Time) (values []*string) {
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

func NewLogTableMetadata(logType, description string) *GlueTableMetadata {
	return &GlueTableMetadata{
		databaseName:  LogProcessingDatabaseName,
		tableName:     standardizeTableName(logType),
		description:   description,
		s3TablePrefix: standardizeS3Prefix(LogS3Prefix, logType),
		timebin:       GlueTableHourly,
		timeUnpadded:  false,
	}
}

func NewRuleTableMetadata(logType, description string) *GlueTableMetadata {
	return &GlueTableMetadata{
		databaseName:  RuleMatchDatabaseName,
		tableName:     standardizeTableName(logType),
		description:   description,
		s3TablePrefix: standardizeS3Prefix(RuleMatchS3Prefix, logType),
		timebin:       GlueTableHourly,
		timeUnpadded:  false,
	}
}

func standardizeTableName(logType string) string {
	// clean table name to make sql friendly
	tableName := strings.Replace(logType, ".", "_", -1) // no '.'
	return strings.ToLower(tableName)
}

func standardizeS3Prefix(s3Prefix, logType string) string {
	return s3Prefix + "/" + standardizeTableName(logType) + "/" // ensure last char is '/'
}

// CreateJSONPartition creates a new JSON partition in a GlueTableMetadata table. If the partition already exists, no partition is added.
func (gm *GlueTableMetadata) CreateJSONPartition(client glueiface.GlueAPI, t time.Time) error {
	partitionPrefix := "s3://" +  gm.PartitionPrefix(t)

	partitionInput := &glue.PartitionInput{
		Values:            gm.partitionValues(t),
		StorageDescriptor: getJSONPartitionDescriptor(partitionPrefix),
	}
	input := &glue.CreatePartitionInput{
		DatabaseName:   aws.String(gm.databaseName),
		TableName:      aws.String(gm.tableName),
		PartitionInput: partitionInput,
	}
	_, err := client.CreatePartition(input)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "AlreadyExistsException" {
				return nil
			}
		}
		return errors.Wrap(err, "failed to create new JSON partition")
	}
	return err
}


// SyncPartition deletes and re-creates a partition using the latest table schema. Used when schemas change.
func (gm *GlueTableMetadata) SyncPartition(client glueiface.GlueAPI, t time.Time) error {
	_, err := gm.deletePartition(client, t)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); !ok || awsErr.Code() != "EntityNotFoundException" {
			return errors.Wrapf(err, "delete partition for %s.%s at %v failed", gm.DatabaseName(), gm.TableName(), t)
		}
	}
	err = gm.CreateJSONPartition(client, t)
	if err != nil {
		return errors.Wrapf(err, "create partition for %s.%s at %v failed", gm.DatabaseName(), gm.TableName(), t)
	}
	return nil
}

func (gm *GlueTableMetadata) deletePartition(client glueiface.GlueAPI, t time.Time) (output *glue.DeletePartitionOutput, err error) {
	input := &glue.DeletePartitionInput{
		DatabaseName:    aws.String(gm.databaseName),
		TableName:       aws.String(gm.tableName),
		PartitionValues: gm.partitionValues(t),
	}
	return client.DeletePartition(input)
}

func getJSONPartitionDescriptor(s3Path string) *glue.StorageDescriptor {
	return &glue.StorageDescriptor{
		InputFormat:  aws.String("org.apache.hadoop.mapred.TextInputFormat"),
		OutputFormat: aws.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
		SerdeInfo: &glue.SerDeInfo{
			SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
			Parameters: map[string]*string{
				"serialization.format": aws.String("1"),
				"case.insensitive":     aws.String("TRUE"), // treat as lower case
			},
		},
		Location: aws.String(s3Path),
	}
}
