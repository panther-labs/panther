package testutils

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
