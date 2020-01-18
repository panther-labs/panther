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

	"github.com/panther-labs/panther/api/lambda/alerts/models"
)

// GetAlert retrieve a AlertItem from DDB
func (table *AlertsTable) GetAlert(alertID *string) (*models.AlertItem, error) {
	input := &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"alertId": {S: alertID},
		},
		TableName: aws.String(table.AlertsTableName),
	}

	ddbResult, err := table.Client.GetItem(input)
	if err != nil {
		return nil, err
	}

	alertItem := &models.AlertItem{}
	if err = dynamodbattribute.UnmarshalMap(ddbResult.Item, alertItem); err != nil {
		return nil, err
	}
	return alertItem, nil
}
