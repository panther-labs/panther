package process

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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/database/models"
	"github.com/panther-labs/panther/internal/core/database_api/athena/testutils"
	"github.com/panther-labs/panther/pkg/awsglue"
	"github.com/panther-labs/panther/pkg/genericapi"
)

/*
	Operation:
	 1) GenerateParquet() is called to kick off a CTAS operation via AthenaAPI
     2) After CTAS has finished Step Function will call this Lambda with UpdateParquetPartition
     3) UpdateParquetPartition() will change the type and location of the partition and delete temp table
*/

const (
	// maxCompactionRetries = 5 // how many times we re-try compacting on error

	ctasDatabase    = "panther_temp" // create temp tables here and delete when done
	ctasSQLTemplate = `
create table %s.%s
with (
  external_location='s3://%s/%s/%s/year=%d/month=%02d/day=%02d/hour=%02d/%s/',
  format='PARQUET', parquet_compression='UNCOMPRESSED'
)
as 
select 
%s
FROM "%s"."%s" where year=%d and month=%d and day=%d and hour=%d order by p_event_time
`
)

var (
	ctasDelay = time.Hour * 2 // how long to wait to convert partition
)

// LambdaInput is the collection of all possible args to the Lambda function used with the genericapi
type LambdaInput struct {
	UpdateParquetPartition *UpdateParquetPartitionInput `json:"updateParquetPartition"`
}

type UpdateParquetPartitionInput struct {
	models.NotifyInput
}

type UpdateParquetPartitionOutput struct {
}

type GenerateParquetInput struct {
	DatabaseName  string
	TableName     string
	BucketName    string
	PartitionHour time.Time
	FailureCount  int // FIXME: add retries
}

func GenerateParquet(input *GenerateParquetInput) (workflowID string, err error) {
	// get the table schema to collect the columns
	tableOutput, err := getTable(input.DatabaseName, input.TableName)
	if err != nil {
		return workflowID, err
	}
	columns := tableOutput.Table.StorageDescriptor.Columns

	// generate a "tag" for the results folder, VERY IMPORTANT, this allows us to repeat without over writing results
	tag := uuid.New().String()

	// generate CTAS sql
	ctasSQL := generateCtasSQL(input.DatabaseName, input.TableName, input.BucketName, columns, input.PartitionHour, tag)

	// generate userData as JSON from inputs so we can update partition when done the Parquet generation in UpdateParquetPartition()
	userData, err := jsoniter.Marshal(input)
	if err != nil {
		return workflowID, errors.WithStack(err)
	}

	// execute CTAS through the Athena API Step Function (non-blocking), call UpdateParquetPartition when done
	var executeAsyncQueryNotifyInput models.ExecuteAsyncQueryNotifyInput
	executeAsyncQueryNotifyInput.DelaySeconds = int(ctasDelay.Seconds())
	executeAsyncQueryNotifyInput.DatabaseName = testutils.TestDb
	executeAsyncQueryNotifyInput.SQL = ctasSQL
	executeAsyncQueryNotifyInput.LambdaName = "panther-datacatalog-updater"
	executeAsyncQueryNotifyInput.MethodName = "updateParquetPartition"
	executeAsyncQueryNotifyInput.UserData = string(userData)
	executeAsyncQueryNotifyInput.UserID = aws.String("panther-datacatalog-updater") // used for logging
	var lambdaInput = struct {
		ExecuteAsyncQueryNotify *models.ExecuteAsyncQueryNotifyInput
	}{
		&executeAsyncQueryNotifyInput,
	}
	var executeAsyncQueryNotifyOutput *models.ExecuteAsyncQueryNotifyOutput
	err = genericapi.Invoke(lambdaClient, "panther-athena-api", &lambdaInput, &executeAsyncQueryNotifyOutput)
	if err != nil {
		return workflowID, errors.WithStack(err)
	}
	workflowID = executeAsyncQueryNotifyOutput.WorkflowID

	return workflowID, nil
}

func UpdateParquetPartition(input *UpdateParquetPartitionInput) (output *UpdateParquetPartitionOutput, err error) {
	zap.L().Info("UpdateParquetPartition", zap.Any("input", input)) // FIXME: remove

	// get the partition that was converted
	var generateParquetInput GenerateParquetInput
	err = jsoniter.Unmarshal([]byte(input.UserData), &generateParquetInput)
	if err != nil {
		return output, errors.Wrapf(err, "cannot unmarshal %s", input.UserData)
	}

	defer func() {
		// ensure we delete the temp table
		tempTableName := generateTempTableName(generateParquetInput.DatabaseName, generateParquetInput.TableName,
			generateParquetInput.PartitionHour)
		deleteTableInput := &glue.DeleteTableInput{
			DatabaseName: aws.String(ctasDatabase),
			Name:         &tempTableName,
		}
		_, deleteErr := glueClient.DeleteTable(deleteTableInput)
		if deleteErr != nil {
			if err != nil {
				err = errors.Wrapf(err, "delete also failed: %s", deleteErr)
			} else {
				err = deleteErr
			}
		}
	}()

	// check if the query was successful
	var getQueryStatusInput models.GetQueryStatusInput
	getQueryStatusInput.QueryID = input.QueryID
	var lambdaInput = struct {
		GetQueryStatus *models.GetQueryStatusInput
	}{
		&getQueryStatusInput,
	}
	var getQueryStatusOutput *models.GetQueryStatusOutput
	err = genericapi.Invoke(lambdaClient, "panther-athena-api", &lambdaInput, &getQueryStatusOutput)
	if err != nil {
		err = errors.Wrapf(err, "invoke panther-athena-api for: %s", input.UserData)
		return output, err
	}
	if getQueryStatusOutput.Status != models.QuerySucceeded {
		err = errors.Errorf("CTAS failed for %s : %s", input.UserData, getQueryStatusOutput.SQLError)
		return output, err
	}

	err = updatePartitionToParquet(&generateParquetInput)
	if err != nil {
		err = errors.Wrapf(err, "cannot update partition %s", input.UserData)
		return output, err
	}

	return output, nil
}

func getTable(databaseName, tableName string) (*glue.GetTableOutput, error) {
	tableInput := &glue.GetTableInput{
		DatabaseName: aws.String(databaseName),
		Name:         aws.String(tableName),
	}
	tableOutput, err := glueClient.GetTable(tableInput)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot get table: %s.%s",
			databaseName, tableName)
	}
	return tableOutput, nil
}

func generateCtasSQL(databaseName, tableName, bucketName string, columns []*glue.Column,
	hour time.Time, tag string) (ctsaSQL string) {

	// collect the columns to make csv
	selectCols := make([]string, len(columns))
	for i := range columns {
		selectCols[i] = `"` + *columns[i].Name + `"` // double quotes needed!
	}

	return fmt.Sprintf(ctasSQLTemplate,
		ctasDatabase, generateTempTableName(databaseName, tableName, hour),
		bucketName, awsglue.GetDataPrefix(databaseName), tableName, hour.Year(), hour.Month(), hour.Day(), hour.Hour(), tag,
		strings.Join(selectCols, ","),
		databaseName, tableName, hour.Year(), hour.Month(), hour.Day(), hour.Hour(),
	)
}

func generateTempTableName(databaseName, tableName string, hour time.Time) string {
	// generate name for table, by using this key it will fail if another is tried concurrently
	return databaseName + "_" + tableName + "_" + hour.Format("2006010215")
}

func updatePartitionToParquet(input *GenerateParquetInput) error {
	// read the temp table
	tableOutput, err := getTable(ctasDatabase, generateTempTableName(input.DatabaseName, input.TableName, input.PartitionHour))
	if err != nil {
		return err
	}

	s3path := *tableOutput.Table.StorageDescriptor.Location

	partitionValues := awsglue.PartitionValuesFromTime(awsglue.GlueTableHourly, input.PartitionHour)

	getPartitionInput := &glue.GetPartitionInput{
		DatabaseName:    aws.String(input.DatabaseName),
		TableName:       aws.String(input.TableName),
		PartitionValues: partitionValues,
	}
	getPartitionOutput, err := glueClient.GetPartition(getPartitionInput)
	if err != nil {
		return errors.Wrapf(err, "cannot get Glue partition for: %s, %#v", s3path, getPartitionInput)
	}

	// configure
	storageDescriptor := *getPartitionOutput.Partition.StorageDescriptor // copy because we will mutate
	storageDescriptor.Location = &s3path                                 // point to Parquet data
	storageDescriptor.InputFormat = aws.String("org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat")
	storageDescriptor.OutputFormat = aws.String("org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat")
	storageDescriptor.SerdeInfo = &glue.SerDeInfo{
		SerializationLibrary: aws.String("org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"),
		Parameters: map[string]*string{
			"serialization.format": aws.String("1"),
		},
	}

	// update
	partitionInput := &glue.PartitionInput{
		Values:            partitionValues,
		StorageDescriptor: &storageDescriptor,
	}
	updatePartitionInput := &glue.UpdatePartitionInput{
		DatabaseName:       aws.String(input.DatabaseName),
		TableName:          aws.String(input.TableName),
		PartitionInput:     partitionInput,
		PartitionValueList: partitionValues,
	}
	_, err = glueClient.UpdatePartition(updatePartitionInput)
	if err != nil {
		return errors.Wrapf(err, "cannot update Glue partition for: %s, %#v", s3path, updatePartitionInput)
	}

	return nil
}
