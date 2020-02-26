package awsglue

import (
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

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

type GluePartition struct {
	datatype models.DataType
	databaseName string
	tableName string
	s3Bucket string
	dataFormat string // Can currently be only "json"
	compression string // Can only be "gzip" currently
	partitionFields []*partitionKeyValue
}

type partitionKeyValue struct {
	column string
	value string
}

func (gp *GluePartition) CreatePartition(client glueiface.GlueAPI) error {
	partitionValues := make([]*string, len(gp.partitionFields))
	for i, field := range gp.partitionFields {
		partitionValues[i] = aws.String(field.value)
	}
	partitionPrefix, err := gp.partitionPrefix()
	if err != nil {
		return err
	}
	partitionInput := &glue.PartitionInput{
		Values:            partitionValues,
		StorageDescriptor: getJSONPartitionDescriptor(partitionPrefix), // We only support JSON currently
	}
	input := &glue.CreatePartitionInput{
		DatabaseName:   aws.String(gp.databaseName),
		TableName:      aws.String(gp.tableName),
		PartitionInput: partitionInput,
	}
	_, err = client.CreatePartition(input)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "AlreadyExistsException" {
				return nil
			}
		}
		return errors.Wrap(err, "failed to create new partition")
	}
	return err
}

func (gp *GluePartition) partitionPrefix() (string, error) {
	tablePrefix:= getTablePrefix(gp.datatype, gp.tableName)
	prefix := "s3://" + gp.s3Bucket + "/" + tablePrefix
	for _, partitionField := range gp.partitionFields {
		prefix += partitionField.column + "=" + partitionField.value + "/"
	}
	return prefix, nil
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

// Gets the partition from S3
func GetPartitionFromS3(s3Bucket, s3ObjectKey string) (*GluePartition, error) {
	zap.L().Info("I got this", zap.String("s3Bucket", s3Bucket), zap.String("s3ObjectKey", s3ObjectKey))
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
	case LogS3Prefix:
		partition.databaseName = LogProcessingDatabaseName
		partition.datatype = models.LogData
	case RuleMatchS3Prefix:
		partition.databaseName = RuleMatchDatabaseName
		partition.datatype = models.RuleData
	default:
		return nil, errors.Errorf("unsupported S3 object prefix %s", s3Keys[0])
	}

	partition.tableName = s3Keys[1]

	yearPartitionKeyValue, err := getTimePartitionColumnField(s3Keys[2], "year")
	if err != nil {
		return nil, err
	}

	partition.partitionFields = []*partitionKeyValue{yearPartitionKeyValue}

	monthPartitionKeyValue, err := getTimePartitionColumnField(s3Keys[3], "month")
	if err != nil {
		return nil, err
	}

	partition.partitionFields = append(partition.partitionFields, monthPartitionKeyValue)
	if len(s3Keys) == 4 {
		// if there are no more fields, stop here
		return partition, nil
	}

	dayPartitionKeyValue, err := getTimePartitionColumnField(s3Keys[4], "day")
	if err != nil {
		return partition, nil
	}
	partition.partitionFields = append(partition.partitionFields, dayPartitionKeyValue)
	if len(s3Keys) == 5 {
		return partition, nil
	}

	hourPartitionKeyValue, err := getTimePartitionColumnField(s3Keys[5], "hour")
	if err != nil {
		return partition, nil
	}
	partition.partitionFields = append(partition.partitionFields, hourPartitionKeyValue)
	return partition, nil
}

func getTimePartitionColumnField(input string, partitionName string) (*partitionKeyValue, error) {
	fields := strings.Split(input, "=")
	if len(fields) != 2 || fields[0] != partitionName {
		return nil, errors.Errorf("failed to get partition column %s from %s", partitionName, input)
	}

	_, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse to integer %s", fields[1])
	}
	return &partitionKeyValue{column: partitionName, value: fields[1]}, nil
}



