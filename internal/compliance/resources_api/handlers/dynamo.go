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
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/resources/models"
)

// The resource struct stored in Dynamo has some different fields compared to the external models.Resource
type resourceItem struct {
	Attributes      models.Attributes      `json:"attributes"`
	Deleted         models.Deleted         `json:"deleted"`
	ID              models.ResourceID      `json:"id"`
	IntegrationID   models.IntegrationID   `json:"integrationId"`
	IntegrationType models.IntegrationType `json:"integrationType"`
	LastModified    models.LastModified    `json:"lastModified"`
	Type            models.ResourceType    `json:"type"`

	// Internal fields: TTL and more efficient filtering
	ExpiresAt int64  `json:"expiresAt,omitempty"`
	LowerID   string `json:"lowerId"` // lowercase ID for efficient ID substring filtering
}

// Convert dynamo item to external models.Resource
func (r *resourceItem) Resource(status models.ComplianceStatus) *models.Resource {
	return &models.Resource{
		Attributes:       r.Attributes,
		ComplianceStatus: status,
		Deleted:          r.Deleted,
		ID:               r.ID,
		IntegrationID:    r.IntegrationID,
		IntegrationType:  r.IntegrationType,
		LastModified:     r.LastModified,
		Type:             r.Type,
	}
}

// Build the table key in the format Dynamo expects
func tableKey(resourceID models.ResourceID) map[string]*dynamodb.AttributeValue {
	return map[string]*dynamodb.AttributeValue{
		"id": {S: aws.String(string(resourceID))},
	}
}

// Build a condition expression if the resource must exist in the table
func existsCondition(resourceID models.ResourceID) expression.ConditionBuilder {
	return expression.Name("id").Equal(expression.Value(resourceID))
}

// Complete a conditional Dynamo update and return the appropriate status code
func doUpdate(update expression.UpdateBuilder, resourceID models.ResourceID) *events.APIGatewayProxyResponse {
	condition := existsCondition(resourceID)
	expr, err := expression.NewBuilder().WithCondition(condition).WithUpdate(update).Build()
	if err != nil {
		zap.L().Error("expr.Build failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	zap.L().Info("submitting dynamo item update",
		zap.String("resourceId", string(resourceID)))
	_, err = dynamoClient.UpdateItem(&dynamodb.UpdateItemInput{
		ConditionExpression:       expr.Condition(),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		Key:                       tableKey(resourceID),
		TableName:                 &env.ResourcesTable,
		UpdateExpression:          expr.Update(),
	})

	if err != nil {
		aerr, ok := err.(awserr.Error)
		if ok && aerr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
		}
		zap.L().Error("dynamoClient.UpdateItem failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return &events.APIGatewayProxyResponse{StatusCode: http.StatusOK}
}

// Wrapper around dynamoClient.ScanPages that accepts a handler function to process each item.
func scanPages(input *dynamodb.ScanInput, handler func(*resourceItem) error) error {
	var handlerErr, unmarshalErr error

	err := dynamoClient.ScanPages(input, func(page *dynamodb.ScanOutput, lastPage bool) bool {
		var items []*resourceItem
		if unmarshalErr = dynamodbattribute.UnmarshalListOfMaps(page.Items, &items); unmarshalErr != nil {
			return false // stop paginating
		}

		for _, entry := range items {
			if handlerErr = handler(entry); handlerErr != nil {
				return false // stop paginating
			}
		}

		return true // keep paging
	})

	if handlerErr != nil {
		zap.L().Error("query item handler failed", zap.Error(handlerErr))
		return handlerErr
	}

	if unmarshalErr != nil {
		zap.L().Error("dynamodbattribute.UnmarshalListOfMaps failed", zap.Error(unmarshalErr))
		return unmarshalErr
	}

	if err != nil {
		zap.L().Error("dynamoClient.QueryPages failed", zap.Error(err))
		return err
	}

	return nil
}
