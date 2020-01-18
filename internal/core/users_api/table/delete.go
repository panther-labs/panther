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
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/genericapi"
)

// Delete removes a row from the table.
func (table *Table) Delete(id *string) error {
	condition := expression.AttributeExists(expression.Name("id"))
	expr, err := expression.NewBuilder().WithCondition(condition).Build()
	if err != nil {
		return &genericapi.InternalError{Message: "dynamo expression build failed: " + err.Error()}
	}

	zap.L().Info("deleting user from dynamo", zap.String("id", *id))
	_, err = table.client.DeleteItem(&dynamodb.DeleteItemInput{
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Key:                       DynamoItem{"id": {S: id}},
		TableName:                 table.Name,
	})

	if err != nil {
		aerr, ok := err.(awserr.Error)
		if ok && aerr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
			return &genericapi.DoesNotExistError{Message: "id=" + *id}
		}
		return &genericapi.AWSError{Method: "dynamodb.DeleteItem", Err: err}
	}

	return nil
}
