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

	"github.com/panther-labs/panther/api/lambda/outputs/models"
)

// GetDefault gets the default outputs for a given severity
func (table *DefaultsTable) GetDefault(severity *string) (*models.DefaultOutputsItem, error) {
	result, err := table.client.GetItem(
		&dynamodb.GetItemInput{
			TableName: table.Name,
			Key: DynamoItem{
				"severity": {S: severity},
			},
			ConsistentRead: aws.Bool(true),
		})

	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, err
	}
	var defaultOutput models.DefaultOutputsItem
	if err = dynamodbattribute.UnmarshalMap(result.Item, &defaultOutput); err != nil {
		return nil, err
	}
	return &defaultOutput, nil
}
