package awsglue

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
)

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

// Meta data about GlueTableMetadata table over parser data written to S3
// NOTE: this struct has all accessor behind functions to allow a lazy evaluation
//       so the cost of creating the schema is only when actually needing this information.

// A partition in Glue containing Panther data
type GluePartition struct {
	datatype         models.DataType
	databaseName     string
	tableName        string
	s3Bucket         string
	dataFormat       string // Can currently be only "json"
	compression      string // Can only be "gzip" currently
	partitionColumns []PartitionColumnInfo
}

func (gp *GluePartition) GetDatabase() string {
	return gp.databaseName
}

func (gp *GluePartition) GetTable() string {
	return gp.tableName
}

func (gp *GluePartition) GetS3Bucket() string {
	return gp.s3Bucket
}

func (gp *GluePartition) GetDataFormat() string {
	return gp.dataFormat
}

func (gp *GluePartition) GetCompression() string {
	return gp.compression
}

func (gp *GluePartition) GetPartitionColumnsInfo() []PartitionColumnInfo {
	return gp.partitionColumns
}

// Based on Timebin(), return an S3 prefix for objects of this table
func getTimePartitionPrefix(timebin GlueTableTimebin, t time.Time) string {
	switch timebin {
	case GlueTableHourly:
		return fmt.Sprintf("year=%d/month=%02d/day=%02d/hour=%02d/", t.Year(), t.Month(), t.Day(), t.Hour())
	case GlueTableDaily:
		return fmt.Sprintf("year=%d/month=%02d/day=%02d/", t.Year(), t.Month(), t.Day())
	default:
		return fmt.Sprintf("year=%d/month=%02d/", t.Year(), t.Month())
	}
}

func GeneratePartitionPrefix(datatype models.DataType, logType string, timebin GlueTableTimebin, time time.Time) string {
	tableName := GetTableName(logType)
	tablePrefix := getTablePrefix(datatype, tableName)
	return tablePrefix + getTimePartitionPrefix(timebin, time)
}

func (gp *GluePartition) GetPartitionPrefix() string {
	tablePrefix := getTablePrefix(gp.datatype, gp.tableName)
	prefix := "s3://" + gp.s3Bucket + "/" + tablePrefix
	for _, partitionField := range gp.partitionColumns {
		prefix += partitionField.Key + "=" + partitionField.Value + "/"
	}
	return prefix
}

// Contains information about partition columns
type PartitionColumnInfo struct {
	Key   string
	Value string
}

// Creates a new partition in Glue using the client provided.
func (gp *GluePartition) CreatePartition(client glueiface.GlueAPI) error {
	partitionValues := make([]*string, len(gp.partitionColumns))
	for i, field := range gp.partitionColumns {
		partitionValues[i] = aws.String(field.Value)
	}
	partitionPrefix := gp.GetPartitionPrefix()
	partitionInput := &glue.PartitionInput{
		Values:            partitionValues,
		StorageDescriptor: getJSONPartitionDescriptor(partitionPrefix), // We only support JSON currently
	}
	input := &glue.CreatePartitionInput{
		DatabaseName:   aws.String(gp.databaseName),
		TableName:      aws.String(gp.tableName),
		PartitionInput: partitionInput,
	}
	_, err := client.CreatePartition(input)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == glue.ErrCodeAlreadyExistsException {
				return nil
			}
		}
		return errors.Wrap(err, "failed to create new partition")
	}
	return nil
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

// Gets the partition from S3bucket and S3 object key info.
// The s3Object key is expected to be in the the format
// `{logs,rules}/{table_name}/year=d{4}/month=d{2}/[day=d{2}/][hour=d{2}/]/{S+}.json.gz` otherwise an error is returned.
func GetPartitionFromS3(s3Bucket, s3ObjectKey string) (*GluePartition, error) {
	partition := &GluePartition{s3Bucket: s3Bucket}

	if !strings.HasSuffix(s3ObjectKey, ".json.gz") {
		return nil, errors.New("currently only GZIP json is supported")
	}
	partition.compression = "gzip"
	partition.dataFormat = "json"

	s3Keys := strings.Split(s3ObjectKey, "/")
	if len(s3Keys) < 4 {
		return nil, errors.Errorf("s3 object key [%s] doesn't have the appropriate format", s3ObjectKey)
	}

	switch s3Keys[0] {
	case logS3Prefix:
		partition.databaseName = LogProcessingDatabaseName
		partition.datatype = models.LogData
	case ruleMatchS3Prefix:
		partition.databaseName = RuleMatchDatabaseName
		partition.datatype = models.RuleData
	default:
		return nil, errors.Errorf("unsupported S3 object prefix %s", s3Keys[0])
	}

	partition.tableName = s3Keys[1]

	yearPartitionKeyValue, err := inferPartitionColumnInfo(s3Keys[2], "year")
	if err != nil {
		return nil, err
	}

	partition.partitionColumns = []PartitionColumnInfo{yearPartitionKeyValue}

	monthPartitionKeyValue, err := inferPartitionColumnInfo(s3Keys[3], "month")
	if err != nil {
		return nil, err
	}

	partition.partitionColumns = append(partition.partitionColumns, monthPartitionKeyValue)
	if len(s3Keys) == 4 {
		// if there are no more fields, stop here
		return partition, nil
	}

	dayPartitionKeyValue, err := inferPartitionColumnInfo(s3Keys[4], "day")
	if err != nil {
		return partition, nil
	}
	partition.partitionColumns = append(partition.partitionColumns, dayPartitionKeyValue)
	if len(s3Keys) == 5 {
		return partition, nil
	}

	hourPartitionKeyValue, err := inferPartitionColumnInfo(s3Keys[5], "hour")
	if err != nil {
		return partition, nil
	}
	partition.partitionColumns = append(partition.partitionColumns, hourPartitionKeyValue)
	return partition, nil
}

func inferPartitionColumnInfo(input string, partitionName string) (PartitionColumnInfo, error) {
	fields := strings.Split(input, "=")
	if len(fields) != 2 || fields[0] != partitionName {
		return PartitionColumnInfo{}, errors.Errorf("failed to get partition key %s from %s", partitionName, input)
	}

	_, err := strconv.Atoi(fields[1])
	if err != nil {
		return PartitionColumnInfo{}, errors.Wrapf(err, "failed to parse to integer %s", fields[1])
	}
	return PartitionColumnInfo{Key: partitionName, Value: fields[1]}, nil
}
