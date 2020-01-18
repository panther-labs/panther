package ddb

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"

	"github.com/panther-labs/panther/api/lambda/snapshot/models"
	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"
	"github.com/panther-labs/panther/pkg/genericapi"
)

var maxElapsedTime = 15 * time.Second

// BatchPutSourceIntegrations adds a batch of new Snapshot Integrations to the database.
func (ddb *DDB) BatchPutSourceIntegrations(input []*models.SourceIntegrationMetadata) error {
	writeRequests := make([]*dynamodb.WriteRequest, len(input))

	// Marshal each new integration and add to the write request
	for i, item := range input {
		item, err := dynamodbattribute.MarshalMap(item)
		if err != nil {
			return &genericapi.AWSError{Err: err, Method: "Dynamodb.MarshalMap"}
		}
		writeRequests[i] = &dynamodb.WriteRequest{PutRequest: &dynamodb.PutRequest{Item: item}}
	}

	// Do the batch write
	err := dynamodbbatch.BatchWriteItem(ddb.Client, maxElapsedTime, &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{ddb.TableName: writeRequests}})
	if err != nil {
		return &genericapi.AWSError{Err: err, Method: "Dynamodb.BatchWriteItem"}
	}

	return nil
}
