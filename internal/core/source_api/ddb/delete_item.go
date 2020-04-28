package ddb

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// DeleteIntegrationItem deletes an integration from the database based on the integration ID
func (ddb *DDB) DeleteIntegrationItem(input *models.DeleteIntegrationInput) error {
	condition := expression.AttributeExists(expression.Name("integrationId"))

	builder := expression.NewBuilder().WithCondition(condition)
	expr, err := builder.Build()
	if err != nil {
		return &genericapi.InternalError{Message: "failed to build DeleteIntegration ddb expression"}
	}

	_, err = ddb.Client.DeleteItem(&dynamodb.DeleteItemInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		ConditionExpression:       expr.Condition(),
		Key: map[string]*dynamodb.AttributeValue{
			hashKey: {S: input.IntegrationID},
		},
		TableName: aws.String(ddb.TableName),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case dynamodb.ErrCodeConditionalCheckFailedException:
				return &genericapi.DoesNotExistError{Message: aerr.Error()}
			default:
				return &genericapi.AWSError{Err: err, Method: "Dynamodb.DeleteItem"}
			}
		}
		return &genericapi.AWSError{Err: err, Method: "Dynamodb.DeleteItem"}
	}

	return nil
}
