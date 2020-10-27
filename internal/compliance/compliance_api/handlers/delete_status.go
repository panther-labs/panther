package handlers

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
	"fmt"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/pkg/awsbatch/dynamodbbatch"
)

// DeleteStatus deletes a batch of items
func (API) DeleteStatus(input *models.DeleteStatusInput) *events.APIGatewayProxyResponse {
	var deleteRequests []*dynamodb.WriteRequest
	for _, entry := range input.Entries {
		var entryRequests []*dynamodb.WriteRequest
		var err error
		if entry.Policy != nil {
			entryRequests, err = policyDeleteEntries(entry.Policy.ID, entry.Policy.ResourceTypes)
		} else {
			entryRequests, err = resourceDeleteEntries(entry.Resource.ID)
		}

		if err != nil {
			zap.L().Error("DeleteStatus failed", zap.Error(err))
			return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		deleteRequests = append(deleteRequests, entryRequests...)
	}

	batchInput := &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]*dynamodb.WriteRequest{Env.ComplianceTable: deleteRequests},
	}

	zap.L().Info("deleting batch of items", zap.Int("itemCount", len(deleteRequests)))
	if err := dynamodbbatch.BatchWriteItem(dynamoClient, maxWriteBackoff, batchInput); err != nil {
		err = fmt.Errorf("dynamodbbatch.BatchWriteItem failed: %s", err)
		zap.L().Error("DeleteStatus failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

// Query the table for entries with the given policyID and return the list of delete requests.
func policyDeleteEntries(policyID string, resourceTypes []string) ([]*dynamodb.WriteRequest, error) {
	zap.L().Debug("querying for deletion", zap.String("policyId", policyID))
	keyCondition := expression.Key("policyId").Equal(expression.Value(policyID))
	projection := expression.NamesList(expression.Name("resourceId"))
	builder := expression.NewBuilder().WithKeyCondition(keyCondition).WithProjection(projection)

	// Filter the entries to just those of a specific resource type
	if len(resourceTypes) > 0 {
		var filter expression.ConditionBuilder

		for i, resourceType := range resourceTypes {
			typeFilter := expression.Equal(expression.Name("resourceType"), expression.Value(resourceType))
			if i == 0 {
				filter = typeFilter
			} else {
				filter = filter.Or(typeFilter)
			}
		}

		builder = builder.WithFilter(filter)
	}

	expr, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("dynamo expression.Build failed: %s", err)
	}

	// NOTE: You can't do a consistent read on a global index
	input := &dynamodb.QueryInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		IndexName:                 &Env.IndexName,
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &Env.ComplianceTable,
	}

	var deleteRequests []*dynamodb.WriteRequest
	err = queryPages(input, func(item *models.ComplianceEntry) error {
		deleteRequests = append(deleteRequests, &dynamodb.WriteRequest{
			DeleteRequest: &dynamodb.DeleteRequest{Key: tableKey(item.ResourceID, policyID)},
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return deleteRequests, nil
}

// Query the table for entries with the given resourceID and return the list of delete requests.
func resourceDeleteEntries(resourceID string) ([]*dynamodb.WriteRequest, error) {
	zap.L().Debug("querying for deletion", zap.String("resourceId", resourceID))
	keyCondition := expression.Key("resourceId").Equal(expression.Value(resourceID))
	projection := expression.NamesList(expression.Name("policyId"))

	expr, err := expression.NewBuilder().WithKeyCondition(keyCondition).WithProjection(projection).Build()
	if err != nil {
		return nil, fmt.Errorf("dynamo expression.Build failed: %s", err)
	}

	input := &dynamodb.QueryInput{
		ConsistentRead:            aws.Bool(true),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &Env.ComplianceTable,
	}

	var deleteRequests []*dynamodb.WriteRequest
	err = queryPages(input, func(item *models.ComplianceEntry) error {
		deleteRequests = append(deleteRequests, &dynamodb.WriteRequest{
			DeleteRequest: &dynamodb.DeleteRequest{Key: tableKey(resourceID, item.PolicyID)},
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return deleteRequests, nil
}
