package users

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

	"github.com/panther-labs/panther/api/lambda/users/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// Get retrieves user to org mapping from the table.
func (table *Table) Get(id *string) (*models.UserItem, error) {
	zap.L().Info("retrieving user from dynamo", zap.String("id", *id))
	response, err := table.client.GetItem(&dynamodb.GetItemInput{
		Key:       DynamoItem{"id": {S: id}},
		TableName: table.Name,
	})
	if err != nil {
		return nil, &genericapi.AWSError{Method: "dynamodb.GetItem", Err: err}
	}

	var user models.UserItem
	if err = dynamodbattribute.UnmarshalMap(response.Item, &user); err != nil {
		return nil, &genericapi.InternalError{
			Message: "failed to unmarshal dynamo item to a User: " + err.Error()}
	}

	if aws.StringValue(user.ID) == "" {
		return nil, &genericapi.DoesNotExistError{Message: "id=" + *id}
	}

	return &user, nil
}
