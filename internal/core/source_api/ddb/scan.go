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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// ScanEnabledIntegrations returns all enabled integrations based on type.
// It performs a DDB scan of the entire table with a filter expression.
func (ddb *DDB) ScanEnabledIntegrations(input *models.ListIntegrationsInput) ([]*models.SourceIntegration, error) {
	filt := expression.And(
		expression.Name("scanEnabled").Equal(expression.Value(true)),
		expression.Name("integrationType").Equal(expression.Value(input.IntegrationType)),
	)
	expr, err := expression.NewBuilder().WithFilter(filt).Build()
	if err != nil {
		return nil, &genericapi.InternalError{Message: "failed to build dynamodb expression"}
	}

	output, err := ddb.Client.Scan(&dynamodb.ScanInput{
		FilterExpression:          expr.Filter(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		TableName:                 aws.String(ddb.TableName),
	})
	if err != nil {
		return nil, &genericapi.AWSError{Err: err, Method: "Dynamodb.Scan"}
	}

	var enabledIntegrations []*models.SourceIntegration
	if err := dynamodbattribute.UnmarshalListOfMaps(output.Items, &enabledIntegrations); err != nil {
		return nil, err
	}

	if enabledIntegrations == nil {
		enabledIntegrations = make([]*models.SourceIntegration, 0)
	}
	return enabledIntegrations, nil
}
