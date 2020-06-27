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
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/pkg/errors"
)

// ScanIntegrations returns all enabled integrations based on type (if type is specified).
// It performs a DDB scan of the entire table with a filter expression.
func (ddb *DDB) ScanIntegrations(integrationType *string) ([]*Integration, error) {
	scanInput := &dynamodb.ScanInput{
		TableName: aws.String(ddb.TableName),
	}
	if integrationType != nil {
		filterExpression := expression.Name("integrationType").Equal(expression.Value(integrationType))
		expr, err := expression.NewBuilder().WithFilter(filterExpression).Build()
		if err != nil {
			return nil, errors.Wrap(err, "failed to build filter expression")
		}
		scanInput.FilterExpression = expr.Filter()
		scanInput.ExpressionAttributeNames = expr.Names()
		scanInput.ExpressionAttributeValues = expr.Values()
	}

	output, err := ddb.Client.Scan(scanInput)
	if err != nil {
		return nil, errors.Wrap(err, "failed to scan table")
	}

	var integrations []*Integration
	if err := dynamodbattribute.UnmarshalListOfMaps(output.Items, &integrations); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal scan results")
	}

	return integrations, nil
}
