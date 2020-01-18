package table

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Get retrieves account details from the table.
func (table *OrganizationsTable) Get() (*models.Organization, error) {
	zap.L().Info("retrieving organization from dynamo")
	response, err := table.client.GetItem(&dynamodb.GetItemInput{
		Key:       DynamoItem{"id": {S: aws.String("1")}},
		TableName: table.Name,
	})
	if err != nil {
		return nil, &genericapi.AWSError{Method: "dynamodb.GetItem", Err: err}
	}

	var org models.Organization
	if err = dynamodbattribute.UnmarshalMap(response.Item, &org); err != nil {
		return nil, &genericapi.InternalError{
			Message: "failed to unmarshal dynamo item to an Organization: " + err.Error()}
	}
	if org.AwsConfig == nil {
		return nil, &genericapi.DoesNotExistError{}
	}

	return &org, nil
}
