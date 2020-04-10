package table

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
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"

	"github.com/panther-labs/panther/pkg/genericapi"
)

// PutOutput saves the output details to the table.
func (table *OutputsTable) PutOutput(output *AlertOutputItem) error {
	item, err := dynamodbattribute.MarshalMap(output)
	if err != nil {
		return &genericapi.InternalError{Message: "failed to marshal AlertOutput to a dynamo item: " + err.Error()}
	}

	input := &dynamodb.PutItemInput{
		Item:                item,
		TableName:           table.Name,
		ConditionExpression: aws.String("attribute_not_exists(outputId)"),
	}

	if _, err = table.client.PutItem(input); err != nil {
		aerr, ok := err.(awserr.Error)
		if ok && aerr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
			return &genericapi.DoesNotExistError{Message: "outputId" + *output.OutputID}
		}
		return &genericapi.AWSError{Method: "dynamodb.PutItem", Err: err}
	}

	return nil
}
