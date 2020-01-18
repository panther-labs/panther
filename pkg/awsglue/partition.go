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
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
)

func (gm *GlueMetadata) CreateJSONPartition(client glueiface.GlueAPI, s3Bucket string, t time.Time) (err error) {
	// inherit StorageDescriptor from table
	tableInput := &glue.GetTableInput{
		DatabaseName: aws.String(gm.databaseName),
		Name:         aws.String(gm.tableName),
	}
	tableOutput, err := client.GetTable(tableInput)
	if err != nil {
		return
	}

	// ensure this is a JSON table, use Contains() because there are multiple json serdes
	if !strings.Contains(*tableOutput.Table.StorageDescriptor.SerdeInfo.SerializationLibrary, "json") {
		err = fmt.Errorf("not a JSON table: %#v", *tableOutput.Table.StorageDescriptor)
		return
	}

	tableOutput.Table.StorageDescriptor.Location = aws.String("s3://" + s3Bucket + "/" + gm.PartitionPrefix(t))

	partitionInput := &glue.PartitionInput{
		Values:            gm.PartitionValues(t),
		StorageDescriptor: tableOutput.Table.StorageDescriptor,
	}
	input := &glue.CreatePartitionInput{
		DatabaseName:   aws.String(gm.databaseName),
		TableName:      aws.String(gm.tableName),
		PartitionInput: partitionInput,
	}
	_, err = client.CreatePartition(input)
	return
}

func (gm *GlueMetadata) GetPartition(client glueiface.GlueAPI, t time.Time) (output *glue.GetPartitionOutput, err error) {
	input := &glue.GetPartitionInput{
		DatabaseName:    aws.String(gm.databaseName),
		TableName:       aws.String(gm.tableName),
		PartitionValues: gm.PartitionValues(t),
	}
	return client.GetPartition(input)
}

func (gm *GlueMetadata) DeletePartition(client glueiface.GlueAPI, t time.Time) (output *glue.DeletePartitionOutput, err error) {
	input := &glue.DeletePartitionInput{
		DatabaseName:    aws.String(gm.databaseName),
		TableName:       aws.String(gm.tableName),
		PartitionValues: gm.PartitionValues(t),
	}
	return client.DeletePartition(input)
}
