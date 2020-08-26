package logtypesapi

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
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
	"context"
	"sort"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

const (
	recordKindStatus      = "status"
	attrAvailableLogTypes = "AvailableLogTypes"
)

type AvailableLogTypes struct {
	LogTypes []string `json:"logTypes"`
}

// ListAvailableLogTypes lists all available log type ids
func (api *API) ListAvailableLogTypes(ctx context.Context) (*AvailableLogTypes, error) {
	ddbInput := dynamodb.GetItemInput{
		TableName:            aws.String(api.TableName),
		ProjectionExpression: aws.String(attrAvailableLogTypes),
		Key: mustMarshalMap(&recordKey{
			RecordID:   "Status",
			RecordKind: recordKindStatus,
		}),
	}
	ddbOutput, err := api.DB.GetItemWithContext(ctx, &ddbInput)
	if err != nil {
		return nil, err
	}
	item := struct {
		AvailableLogTypes []string
	}{}
	if err := dynamodbattribute.UnmarshalMap(ddbOutput.Item, &item); err != nil {
		return nil, err
	}

	logTypes := api.NativeLogTypes.LogTypes()
	logTypes = append(logTypes, item.AvailableLogTypes...)
	sort.Strings(logTypes)
	return &AvailableLogTypes{
		LogTypes: logTypes,
	}, nil
}

func mustMarshalMap(val interface{}) map[string]*dynamodb.AttributeValue {
	attr, err := dynamodbattribute.MarshalMap(val)
	if err != nil {
		panic(err)
	}
	return attr
}

type recordKey struct {
	RecordID   string
	RecordKind string
}
