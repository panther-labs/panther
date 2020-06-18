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
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/pkg/errors"
)

func (ddb *DDB) UpdateStatus(integrationID string, status IntegrationStatus) error {
	updateExpression := expression.Set(expression.Name("lastEventReceived"), expression.Value(status.LastEventReceived))
	expr, err := expression.NewBuilder().WithUpdate(updateExpression).Build()
	if err != nil {
		return errors.Wrap(err, "failed to generate update expression")
	}
	updateRequest := &dynamodb.UpdateItemInput{
		TableName: aws.String(ddb.TableName),
		Key: map[string]*dynamodb.AttributeValue{
			hashKey: {S: &integrationID},
		},
		UpdateExpression:          expr.Update(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
	}

	_, err = ddb.Client.UpdateItem(updateRequest)
	if err != nil {
		return errors.Wrap(err, "failed to update item")
	}
	return nil
}
