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
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
)

const (
	logS3Prefix       = "logs"
	ruleMatchS3Prefix = "rules"

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

// Metadata about Glue table
type GlueTableMetadata struct {
	databaseName string
	tableName    string
	description  string
	logType      string
	prefix       string
	timebin      GlueTableTimebin // at what time resolution is this table partitioned
	eventStruct  interface{}
}

// Creates a new GlueTableMetadata object
func NewGlueTableMetadata(
	datatype models.DataType, logType, logDescription string, timebin GlueTableTimebin, eventStruct interface{}) *GlueTableMetadata {

	tableName := GetTableName(logType)
	tablePrefix := getTablePrefix(datatype, tableName)
	return &GlueTableMetadata{
		databaseName: getDatabase(datatype),
		tableName:    tableName,
		description:  logDescription,
		timebin:      timebin,
		logType:      logType,
		prefix:       tablePrefix,
		eventStruct:  eventStruct,
	}
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
func (gm *GlueTableMetadata) Prefix() string {
	return gm.prefix
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

// The partition keys for this table
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

// Based on Timebin(), return an S3 prefix for objects of this table
func (gm *GlueTableMetadata) GetPartitionPrefix(t time.Time) string {
	prefix := gm.Prefix()
	return prefix + getTimePartitionPrefix(gm.timebin, t)
}

// Returns the prefix of the table in S3 or error if it failed to generate it
func getDatabase(dataType models.DataType) string {
	if dataType == models.LogData {
		return LogProcessingDatabaseName
	}
	return RuleMatchDatabaseName
}

// Returns the prefix of the table in S3 or error if it failed to generate it
func getTablePrefix(dataType models.DataType, tableName string) string {
	if dataType == models.LogData {
		return logS3Prefix + "/" + tableName + "/"
	}
	return ruleMatchS3Prefix + "/" + tableName + "/"
}

func GetTableName(logType string) string {
	// clean table name to make sql friendly
	tableName := strings.Replace(logType, ".", "_", -1) // no '.'
	return strings.ToLower(tableName)
}

// SyncPartitions updates a table's partitions using the latest table schema. Used when schemas change.
func (gm *GlueTableMetadata) SyncPartitions(glueClient glueiface.GlueAPI, s3Client s3iface.S3API, startDate time.Time) (failed error) {
	// inherit StorageDescriptor from table
	tableInput := &glue.GetTableInput{
		DatabaseName: aws.String(gm.databaseName),
		Name:         aws.String(gm.tableName),
	}
	tableOutput, failed := glueClient.GetTable(tableInput)
	if failed != nil {
		return failed
	}

	columns := tableOutput.Table.StorageDescriptor.Columns
	if startDate.IsZero() {
		startDate = *tableOutput.Table.CreateTime
	}
	startDate = startDate.Truncate(time.Hour * 24) // clip to beginning of day
	// update to current day at last hour
	endDay := time.Now().UTC().Truncate(time.Hour * 24).Add(time.Hour * 23)

	const concurrency = 10
	updateChan := make(chan time.Time, concurrency)
	// update concurrently cuz the Glue API is very slow
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			for update := range updateChan {
				if failed != nil {
					continue // drain channel
				}

				getPartitionInput := &glue.GetPartitionInput{
					DatabaseName:    aws.String(gm.databaseName),
					TableName:       aws.String(gm.tableName),
					PartitionValues: gm.partitionValues(update),
				}
				getPartitionOutput, err := glueClient.GetPartition(getPartitionInput)
				if err != nil {
					// skip time period with no partition UNLESS there is data, then create
					if awsErr, ok := err.(awserr.Error); !ok || awsErr.Code() != glue.ErrCodeEntityNotFoundException {
						failed = err
					} else { // no partition, check if there is data in S3, if so, create
						if hasData, err := gm.partitionHasData(s3Client, update, tableOutput); err != nil {
							failed = err
						} else if hasData {
							if err = gm.createPartition(glueClient, update, tableOutput); err != nil {
								failed = err
							}
						}
					}
					continue
				}

				// leave _everything_ the same except the schema
				getPartitionOutput.Partition.StorageDescriptor.Columns = columns
				values := gm.partitionValues(update)
				partitionInput := &glue.PartitionInput{
					Values:            values,
					StorageDescriptor: getPartitionOutput.Partition.StorageDescriptor,
				}
				updatePartitionInput := &glue.UpdatePartitionInput{
					DatabaseName:       aws.String(gm.databaseName),
					TableName:          aws.String(gm.tableName),
					PartitionInput:     partitionInput,
					PartitionValueList: values,
				}
				_, err = glueClient.UpdatePartition(updatePartitionInput)
				if err != nil {
					failed = err
					continue
				}
			}
			wg.Done()
		}()
	}

	// loop over each partition updating
	for timeBin := startDate; !timeBin.After(endDay); timeBin = gm.Timebin().Next(timeBin) {
		updateChan <- timeBin
	}

	close(updateChan)
	wg.Wait()

	return failed
}

// Deprecated - use GluePartition.CreatePartition instead
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

	return gm.createPartition(client, t, tableOutput)
}

func (gm *GlueTableMetadata) createPartition(client glueiface.GlueAPI, t time.Time, tableOutput *glue.GetTableOutput) error {
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
		if awsErr, ok := err.(awserr.Error); !ok || awsErr.Code() != glue.ErrCodeAlreadyExistsException {
			return err
		}
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

func (gm *GlueTableMetadata) partitionHasData(client s3iface.S3API, t time.Time, tableOutput *glue.GetTableOutput) (bool, error) {
	location, err := url.Parse(*tableOutput.Table.StorageDescriptor.Location)
	if err != nil {
		return false, errors.Wrapf(err, "Cannot parse table %s.%s s3 path: %s",
			gm.DatabaseName(), gm.TableName(),
			*tableOutput.Table.StorageDescriptor.Location)
	}

	// list files w/pagination
	inputParams := &s3.ListObjectsV2Input{
		Bucket:  aws.String(location.Host),
		Prefix:  aws.String(gm.GetPartitionPrefix(t)),
		MaxKeys: aws.Int64(1), // look for at least 1
	}
	var hasData bool
	err = client.ListObjectsV2Pages(inputParams, func(page *s3.ListObjectsV2Output, isLast bool) bool {
		for _, value := range page.Contents {
			if *value.Size > 0 { // we only care about objects with size
				hasData = true
			}
		}
		return false // "To stop iterating, return false from the fn function."
	})

	return hasData, err
}

// Based on Timebin(), return an []*string values (used for Glue APIs)
func (gm *GlueTableMetadata) partitionValues(t time.Time) (values []*string) {
	values = []*string{aws.String(fmt.Sprintf("%d", t.Year()))}

	if gm.timebin >= GlueTableMonthly {
		values = append(values, aws.String(fmt.Sprintf("%02d", t.Month())))
	}
	if gm.timebin >= GlueTableDaily {
		values = append(values, aws.String(fmt.Sprintf("%02d", t.Day())))
	}
	if gm.timebin >= GlueTableHourly {
		values = append(values, aws.String(fmt.Sprintf("%02d", t.Hour())))
	}
	return
}
