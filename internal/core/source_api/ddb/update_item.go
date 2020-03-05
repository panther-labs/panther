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
	"reflect"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// UpdateItem updates existing attributes in an item in the table.
//
// It inspects the input struct to identify non-nil fields, and then only updates them.
func (ddb *DDB) UpdateItem(input *UpdateIntegrationItem) (*models.SourceIntegration, error) {
	var update expression.UpdateBuilder
	val := reflect.ValueOf(input).Elem()
	st := reflect.TypeOf(input).Elem()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)

		if field.IsNil() {
			continue
		}

		switch st.Field(i).Name {
		// Skip primary key attributes
		case "IntegrationID":
			continue
		}

		// The update expression builds on itself, and then is added to
		// the builder after iterating through the input struct.
		if keyName, ok := st.Field(i).Tag.Lookup("json"); ok {
			switch field.Kind() {
			case reflect.Ptr:
				update = update.Set(
					expression.Name(keyName),
					expression.Value(field.Elem().Interface()),
				)
			default:
				update = update.Set(
					expression.Name(keyName),
					expression.Value(field.Interface()),
				)
			}
		}
	}

	builder := expression.NewBuilder().WithUpdate(update)
	expr, err := builder.Build()
	if err != nil {
		return nil, &genericapi.InternalError{Message: err.Error()}
	}

	zap.L().Debug(
		"update item input",
		zap.String("updateExpression", *expr.Update()),
		zap.Any("expressionAttributeNames", expr.Names()),
		zap.Any("expressionAttributeValues", expr.Values()),
	)

	response, err := ddb.Client.UpdateItem(&dynamodb.UpdateItemInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Key: map[string]*dynamodb.AttributeValue{
			hashKey: {S: input.IntegrationID},
		},
		ReturnValues:     aws.String("ALL_NEW"),
		TableName:        aws.String(ddb.TableName),
		UpdateExpression: expr.Update(),
	})
	if err != nil {
		return nil, &genericapi.AWSError{Err: err, Method: "Dynamodb.UpdateItem"}
	}

	var result models.SourceIntegration
	if err = dynamodbattribute.UnmarshalMap(response.Attributes, &result); err != nil {
		return nil, &genericapi.InternalError{Message: "update unmarshal failed: " + err.Error()}
	}

	return &result, nil
}
