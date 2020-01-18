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

	"github.com/panther-labs/panther/api/lambda/organization/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Put writes organization details to the dynamo table.
func (table *OrganizationsTable) Put(org *models.Organization) error {
	item, err := dynamodbattribute.MarshalMap(org)
	if err != nil {
		return &genericapi.InternalError{
			Message: "failed to marshal Organization to a dynamo item: " + err.Error()}
	}

	item["id"] = &dynamodb.AttributeValue{S: aws.String("1")}
	input := &dynamodb.PutItemInput{Item: item, TableName: table.Name}
	if _, err = table.client.PutItem(input); err != nil {
		return &genericapi.AWSError{Method: "dynamodb.PutItem", Err: err}
	}

	return nil
}
