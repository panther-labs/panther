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
	"net/url"
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
	s3Prefix string
	timebin       GlueTableTimebin // at what time resolution is this table partitioned
	eventStruct interface{}
}

func NewLogTableMetadata(logType, logDescription string, eventStruct interface{}) *GlueTableMetadata{
	tableName := standardizeTableName(logType)
	return &GlueTableMetadata{
		databaseName:  LogProcessingDatabaseName,
		tableName:     tableName,
		description:   logDescription,
		timebin:       GlueTableHourly,
		logType: logType,
		s3Prefix: LogS3Prefix + "/" + tableName + "/",
		eventStruct: eventStruct,
	}
}

func NewRuleTableMetadata(logType, logDescription string, eventStruct interface{}) *GlueTableMetadata{
	tableName := standardizeTableName(logType)
	return &GlueTableMetadata{
		databaseName:  RuleMatchDatabaseName,
		tableName:     tableName,
		description:   logDescription,
		timebin:       GlueTableHourly,
		logType: logType,
		s3Prefix: RuleMatchS3Prefix + "/" + tableName + "/",
		eventStruct: eventStruct,
	}
}


func standardizeTableName(logType string) string {
	// clean table name to make sql friendly
	tableName := strings.Replace(logType, ".", "_", -1) // no '.'
	return strings.ToLower(tableName)
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

// All data for this table are stored in this S3 prefix
func (gm *GlueTableMetadata) S3Prefix() string {
	return gm.s3Prefix
}

func (gm *GlueTableMetadata) Timebin() GlueTableTimebin {
	return gm.timebin
}

func (gm *GlueTableMetadata) LogType() string {
	return gm.logType
}

func (gm *GlueTableMetadata) EventStruct() interface{} {
	return gm.eventStruct
}

func (gm *GlueTableMetadata) PartitionKeys() (partitions []PartitionKey) {
	partitions = []PartitionKey{{Name: "year", Type: "int"}}

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
func (gm *GlueTableMetadata) GetPartitionPrefix(t time.Time) (prefix string) {
	prefix = gm.S3Prefix()
	switch gm.timebin {
	case GlueTableHourly:
		prefix += fmt.Sprintf("year=%02d/month=%02d/day=%02d/hour=%02d/", t.Year(), t.Month(), t.Day(), t.Hour())
	case GlueTableDaily:
		prefix += fmt.Sprintf("year=%02d/month=%02d/day=%02d/", t.Year(), t.Month(), t.Day())
	case GlueTableMonthly:
		prefix += fmt.Sprintf("year=%02d/month=%02d/", t.Year(), t.Month())
	}
	return
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

func (gm *GlueTableMetadata) CreateJSONPartition(client glueiface.GlueAPI, t time.Time) error {
	// inherit StorageDescriptor from table
	tableInput := &glue.GetTableInput{
		DatabaseName: aws.String(gm.databaseName),
		Name:         aws.String(gm.tableName),
	}
	tableOutput, err := client.GetTable(tableInput)
	if err != nil {
		return err
	}

	// ensure this is a JSON table, use Contains() because there are multiple json serdes
	if !strings.Contains(*tableOutput.Table.StorageDescriptor.SerdeInfo.SerializationLibrary, "json") {
		return errors.Errorf("not a JSON table: %#v", *tableOutput.Table.StorageDescriptor)
	}

	location, err := url.Parse(*tableOutput.Table.StorageDescriptor.Location)
	if err != nil {
		return errors.Wrapf(err, "Cannot parse table %s.%s s3 path: %s",
			gm.DatabaseName(), gm.TableName(),
			*tableOutput.Table.StorageDescriptor.Location)
	}

	tableOutput.Table.StorageDescriptor.Location = aws.String("s3://" + location.Host + "/" + gm.GetPartitionPrefix(t))

	partitionInput := &glue.PartitionInput{
		Values:            gm.partitionValues(t),
		StorageDescriptor: tableOutput.Table.StorageDescriptor,
	}
	input := &glue.CreatePartitionInput{
		DatabaseName:   aws.String(gm.databaseName),
		TableName:      aws.String(gm.tableName),
		PartitionInput: partitionInput,
	}
	_, err = client.CreatePartition(input)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); !ok || awsErr.Code() != "EntityNotFoundException" {
			return err
		}
	}
	return nil
}

// Based on Timebin(), return an []*string values (used for GlueTableMetadata APIs)
func (gm *GlueTableMetadata) partitionValues(t time.Time) (values []*string) {
	var intFormat string

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
