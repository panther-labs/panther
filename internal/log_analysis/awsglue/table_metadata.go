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
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
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

// Creates a new GlueTableMetadata object for Panther log sources
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

// NewLogTableMetadata is a convenience function to define log data table metadata with hourly resolution
func NewLogTableMetadata(logType, desc string, eventStruct interface{}) *GlueTableMetadata {
	return NewGlueTableMetadata(models.LogData, logType, desc, GlueTableHourly, eventStruct)
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

func (gm *GlueTableMetadata) HasPartitions(glueClient glueiface.GlueAPI) (bool, error) {
	return TableHasPartitions(glueClient, gm.databaseName, gm.tableName)
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
	return gm.Prefix() + gm.timebin.PartitionS3PathFromTime(t)
}

// SyncPartitions updates a table's partitions using the latest table schema. Used when schemas change.
func (gm *GlueTableMetadata) SyncPartitions(glueClient glueiface.GlueAPI, s3Client s3iface.S3API, startDate time.Time) error {
	// inherit StorageDescriptor from table
	tableInput := &glue.GetTableInput{
		DatabaseName: aws.String(gm.databaseName),
		Name:         aws.String(gm.tableName),
	}
	tableOutput, err := glueClient.GetTable(tableInput)
	if err != nil {
		return err
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
	errChan := make(chan error, concurrency)
	// update concurrently cuz the Glue API is very slow
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			failed := false
			for update := range updateChan {
				if failed {
					continue // drain channel
				}

				values := gm.timebin.PartitionValuesFromTime(update)

				getPartitionOutput, err := GetPartition(glueClient, gm.databaseName, gm.tableName, values)
				if err != nil {
					// skip time period with no partition UNLESS there is data, then create
					if awsErr, ok := err.(awserr.Error); !ok || awsErr.Code() != glue.ErrCodeEntityNotFoundException {
						failed = true
						errChan <- err
					} else { // no partition, check if there is data in S3, if so, create
						if hasData, err := gm.timebin.PartitionHasData(s3Client, update, tableOutput); err != nil {
							failed = true
							errChan <- err
						} else if hasData {
							if _, err = gm.createPartition(glueClient, update, tableOutput); err != nil {
								failed = true
								errChan <- err
							}
						}
					}
					continue
				}

				// leave _everything_ the same except the schema, and the serde info to get column mappings
				storageDescriptor := *getPartitionOutput.Partition.StorageDescriptor // copy because we will mutate
				storageDescriptor.Columns = columns
				// we need to update the SerDeInfo for JSON partitions to get the column mappings
				if IsJSONPartition(&storageDescriptor) {
					storageDescriptor.SerdeInfo = tableOutput.Table.StorageDescriptor.SerdeInfo
				}
				_, err = UpdatePartition(glueClient, gm.databaseName, gm.tableName, values,
					&storageDescriptor, nil)
				if err != nil {
					failed = true
					errChan <- err
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

	close(errChan)
	return <-errChan
}

func (gm *GlueTableMetadata) CreateJSONPartition(client glueiface.GlueAPI, t time.Time) (created bool, err error) {
	// inherit StorageDescriptor from table
	tableOutput, err := GetTable(client, gm.databaseName, gm.tableName)
	if err != nil {
		return false, err
	}

	// ensure this is a JSON table, use Contains() because there are multiple json serdes
	if !IsJSONPartition(tableOutput.Table.StorageDescriptor) {
		return false, errors.Errorf("not a JSON table: %#v", *tableOutput.Table.StorageDescriptor)
	}

	return gm.createPartition(client, t, tableOutput)
}

func (gm *GlueTableMetadata) createPartition(client glueiface.GlueAPI, t time.Time,
	tableOutput *glue.GetTableOutput) (created bool, err error) {

	bucket, _, err := ParseS3URL(*tableOutput.Table.StorageDescriptor.Location)
	if err != nil {
		return false, err
	}

	storageDescriptor := *tableOutput.Table.StorageDescriptor // copy because we will mutate
	storageDescriptor.Location = aws.String("s3://" + bucket + "/" + gm.GetPartitionPrefix(t))

	_, err = CreatePartition(client, gm.databaseName, gm.tableName, gm.timebin.PartitionValuesFromTime(t),
		&storageDescriptor, nil)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == glue.ErrCodeAlreadyExistsException {
			return false, nil // no error
		}
		return false, err
	}
	return true, nil
}

// get partition, return nil if it does not exist
func (gm *GlueTableMetadata) GetPartition(client glueiface.GlueAPI, t time.Time) (output *glue.GetPartitionOutput, err error) {
	output, err = GetPartition(client, gm.databaseName, gm.tableName, gm.timebin.PartitionValuesFromTime(t))
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == glue.ErrCodeEntityNotFoundException {
			return nil, nil // not there, no error
		}
		return nil, err
	}
	return output, err
}

func (gm *GlueTableMetadata) deletePartition(client glueiface.GlueAPI, t time.Time) (output *glue.DeletePartitionOutput, err error) {
	return DeletePartition(client, gm.databaseName, gm.tableName, gm.timebin.PartitionValuesFromTime(t))
}
