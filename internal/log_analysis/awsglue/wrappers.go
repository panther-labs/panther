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
	"context"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/glue/glueiface"
	"github.com/pkg/errors"
	"go.uber.org/multierr"

	"github.com/panther-labs/panther/internal/core/pantherdb"
	"github.com/panther-labs/panther/pkg/awsutils"
)

// Wrapper functions to reduce boiler-plate code in callers

func CreateDatabase(client glueiface.GlueAPI, name, description string) (*glue.CreateDatabaseOutput, error) {
	createDatabaseInput := &glue.CreateDatabaseInput{
		DatabaseInput: &glue.DatabaseInput{
			Name:        aws.String(name),
			Description: aws.String(description),
		},
	}
	return client.CreateDatabase(createDatabaseInput)
}

func DeleteDatabase(client glueiface.GlueAPI, name string) (*glue.DeleteDatabaseOutput, error) {
	deleteDatabaseInput := &glue.DeleteDatabaseInput{
		Name: aws.String(name),
	}
	return client.DeleteDatabase(deleteDatabaseInput)
}

func GetTable(client glueiface.GlueAPI, databaseName, tableName string) (*glue.GetTableOutput, error) {
	tableInput := &glue.GetTableInput{
		DatabaseName: aws.String(databaseName),
		Name:         aws.String(tableName),
	}
	return client.GetTable(tableInput)
}

func DeleteTable(client glueiface.GlueAPI, databaseName, tableName string) (*glue.DeleteTableOutput, error) {
	deleteTableInput := &glue.DeleteTableInput{
		DatabaseName: aws.String(databaseName),
		Name:         aws.String(tableName),
	}
	return client.DeleteTable(deleteTableInput)
}

func TableHasPartitions(client glueiface.GlueAPI, databaseName, tableName string) (hasData bool, err error) {
	gluePartitionOutput, err := client.GetPartitions(&glue.GetPartitionsInput{
		DatabaseName: &databaseName,
		TableName:    &tableName,
		MaxResults:   aws.Int64(1),
	})
	if err == nil && len(gluePartitionOutput.Partitions) > 0 {
		hasData = true
	}
	return hasData, err
}

func CreatePartition(client glueiface.GlueAPI, databaseName, tableName string,
	partitionValues []*string, storageDescriptor *glue.StorageDescriptor,
	parameters map[string]*string) (*glue.CreatePartitionOutput, error) {

	partitionInput := &glue.PartitionInput{
		Values:            partitionValues,
		StorageDescriptor: storageDescriptor,
		Parameters:        parameters,
	}
	createPartitionInput := &glue.CreatePartitionInput{
		DatabaseName:   aws.String(databaseName),
		TableName:      aws.String(tableName),
		PartitionInput: partitionInput,
	}
	return client.CreatePartition(createPartitionInput)
}

func GetPartition(client glueiface.GlueAPI, databaseName, tableName string,
	partitionValues []*string) (*glue.GetPartitionOutput, error) {

	getPartitionInput := &glue.GetPartitionInput{
		DatabaseName:    aws.String(databaseName),
		TableName:       aws.String(tableName),
		PartitionValues: partitionValues,
	}
	return client.GetPartition(getPartitionInput)
}

func DeletePartition(client glueiface.GlueAPI, databaseName, tableName string,
	partitionValues []*string) (*glue.DeletePartitionOutput, error) {

	getPartitionInput := &glue.DeletePartitionInput{
		DatabaseName:    aws.String(databaseName),
		TableName:       aws.String(tableName),
		PartitionValues: partitionValues,
	}
	return client.DeletePartition(getPartitionInput)
}

func UpdatePartition(client glueiface.GlueAPI, databaseName, tableName string,
	partitionValues []*string, storageDescriptor *glue.StorageDescriptor,
	parameters map[string]*string) (*glue.UpdatePartitionOutput, error) {

	partitionInput := &glue.PartitionInput{
		Values:            partitionValues,
		StorageDescriptor: storageDescriptor,
		Parameters:        parameters,
	}
	updatePartitionInput := &glue.UpdatePartitionInput{
		DatabaseName:       aws.String(databaseName),
		TableName:          aws.String(tableName),
		PartitionInput:     partitionInput,
		PartitionValueList: partitionValues,
	}
	return client.UpdatePartition(updatePartitionInput)
}

func IsJSONPartition(storageDescriptor *glue.StorageDescriptor) bool {
	return strings.Contains(strings.ToLower(*storageDescriptor.SerdeInfo.SerializationLibrary), "json")
}

func ParseS3URL(s3URL string) (bucket, key string, err error) {
	parsedPath, err := url.Parse(s3URL)
	if err != nil {
		return bucket, key, err
	}

	if parsedPath.Scheme != "s3" {
		return bucket, key, errors.Errorf("not s3 protocol (expecting s3://): %s,", s3URL)
	}

	bucket = parsedPath.Host
	if bucket == "" {
		return bucket, key, errors.Errorf("missing bucket: %s,", s3URL)
	}

	if len(parsedPath.Path) > 0 {
		key = parsedPath.Path[1:] // remove leading '/'
	}

	return bucket, key, err
}

func EnsureDatabases(ctx context.Context, client glueiface.GlueAPI) (err error) {
	for name, desc := range pantherdb.Registry {
		if e := EnsureDatabase(ctx, client, name, desc); e != nil {
			err = multierr.Append(err, e)
		}
	}
	return
}

func EnsureDatabase(ctx context.Context, client glueiface.GlueAPI, name, description string) error {
	createDatabaseInput := &glue.CreateDatabaseInput{
		DatabaseInput: &glue.DatabaseInput{
			Name:        aws.String(name),
			Description: aws.String(description),
		},
	}
	_, err := client.CreateDatabaseWithContext(ctx, createDatabaseInput)
	if err != nil && !awsutils.IsAnyError(err, glue.ErrCodeAlreadyExistsException) {
		return err
	}
	return nil
}
