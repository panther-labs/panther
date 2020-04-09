package ddb

/**
 * A Cloud-Native SIEM for the Modern Security Team
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

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// GetIntegration returns an integration by its ID
func (ddb *DDB) GetIntegration(integrationID *string) (*models.SourceIntegrationMetadata, error) {
	output, err := ddb.Client.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(ddb.TableName),
		Key: map[string]*dynamodb.AttributeValue{
			hashKey: {S: integrationID},
		},
	})
	if err != nil {
		return nil, &genericapi.AWSError{Err: err, Method: "Dynamodb.GetItem"}
	}

	var integration models.SourceIntegrationMetadata
	if output.Item == nil {
		return nil, err
	}
	if err := dynamodbattribute.UnmarshalMap(output.Item, &integration); err != nil {
		return nil, err
	}

	return &integration, nil
}
