package testutils

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"
	"github.com/panther-labs/panther/pkg/awsbatch/s3batch"
)

const maxBackoff = 10 * time.Second

// ClearDynamoTable deletes all items from the table.
//
// Automatic table backups are not affected.
func ClearDynamoTable(awsSession *session.Session, tableName string) error {
	// Describe the table to determine the name of the hash/range keys
	client := dynamodb.New(awsSession)
	details, err := client.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		return err
	}

	var attrNames []string
	for _, item := range details.Table.KeySchema {
		attrNames = append(attrNames, aws.StringValue(item.AttributeName))
	}

	input := &dynamodb.ScanInput{
		ConsistentRead:       aws.Bool(true),
		ProjectionExpression: aws.String(strings.Join(attrNames, ",")),
		TableName:            aws.String(tableName),
	}
	var deleteRequests []*dynamodb.WriteRequest

	// Scan all table items
	err = client.ScanPages(input, func(page *dynamodb.ScanOutput, lastPage bool) bool {
		for _, item := range page.Items {
			deleteRequests = append(deleteRequests, &dynamodb.WriteRequest{
				DeleteRequest: &dynamodb.DeleteRequest{Key: item},
			})
		}
		return true
	})
	if err != nil {
		return err
	}

	// Batch delete all items
	return dynamodbbatch.BatchWriteItem(client, maxBackoff, &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{tableName: deleteRequests},
	})
}

// ClearS3Bucket deletes all object versions from the bucket.
func ClearS3Bucket(awsSession *session.Session, bucketName string) error {
	client := s3.New(awsSession)
	input := &s3.ListObjectVersionsInput{Bucket: aws.String(bucketName)}
	var objectVersions []*s3.ObjectIdentifier

	// List all object versions (including delete markers)
	err := client.ListObjectVersionsPages(
		input,
		func(page *s3.ListObjectVersionsOutput, lastPage bool) bool {
			for _, marker := range page.DeleteMarkers {
				objectVersions = append(objectVersions, &s3.ObjectIdentifier{
					Key: marker.Key, VersionId: marker.VersionId})
			}

			for _, version := range page.Versions {
				objectVersions = append(objectVersions, &s3.ObjectIdentifier{
					Key: version.Key, VersionId: version.VersionId})
			}
			return true
		},
	)
	if err != nil {
		return err
	}

	// Batch delete all objects
	return s3batch.DeleteObjects(client, maxBackoff, &s3.DeleteObjectsInput{
		Bucket: aws.String(bucketName),
		Delete: &s3.Delete{Objects: objectVersions},
	})
}
