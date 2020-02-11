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
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"
)

func (gm *GlueMetadata) CreateJSONPartition(client glueiface.GlueAPI, t time.Time) error {
	// check first if present, avoids extra API calls and "AlreadyExistsException" errors in CloudTrail logs
	if _, getPartitionErr := gm.GetPartition(client, t); getPartitionErr != nil {
		if awsErr, ok := getPartitionErr.(awserr.Error); !ok || awsErr.Code() != "EntityNotFoundException" {
			return getPartitionErr
		}
	} else {
		// return exception err same as CreatePartition() when the partition exists
		return awserr.New("AlreadyExistsException", "AlreadyExistsException", nil)
	}

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

	tableOutput.Table.StorageDescriptor.Location = aws.String("s3://" + location.Host + "/" + gm.PartitionPrefix(t))

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
	return err
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

// SyncPartition deletes and re-creates a partition using the latest table schema. Used when schemas change.
func (gm *GlueMetadata) SyncPartition(client glueiface.GlueAPI, t time.Time) error {
	_, err := gm.DeletePartition(client, t)
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
