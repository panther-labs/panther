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
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"

	"github.com/panther-labs/panther/api/lambda/outputs/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// GetDefaults returns the default outputs for one organization
func (table *DefaultsTable) GetDefaults() (defaults []*models.DefaultOutputsItem, err error) {
	var scanInput = &dynamodb.ScanInput{
		TableName: table.Name,
	}

	var internalErr error
	queryErr := table.client.ScanPages(scanInput,
		func(page *dynamodb.ScanOutput, lastPage bool) bool {
			var defaultsPartial []*models.DefaultOutputsItem
			if internalErr = dynamodbattribute.UnmarshalListOfMaps(page.Items, &defaultsPartial); internalErr != nil {
				internalErr = &genericapi.InternalError{
					Message: "failed to unmarshal dynamo item to an AlertOutputItem: " + internalErr.Error(),
				}
				return false
			}
			defaults = append(defaults, defaultsPartial...)
			return true
		})

	if queryErr != nil {
		return nil, &genericapi.AWSError{Err: queryErr, Method: "dynamodb.ScanPages"}
	}
	if internalErr != nil {
		return nil, &genericapi.InternalError{
			Message: "failed to unmarshal dynamo items: " + internalErr.Error()}
	}

	return defaults, nil
}
