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
	"net/url"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// GetStatus retrieves a single policy/resource status pair from the Dynamo table.
func (API) GetStatus(input *models.GetStatusInput) *events.APIGatewayProxyResponse {
	var err error
	input.PolicyID, err = url.QueryUnescape(input.PolicyID)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("policyId '%s' could not be url-escaped: %s", input.PolicyID, err),
			StatusCode: http.StatusBadRequest,
		}
	}
	input.ResourceID, err = url.QueryUnescape(input.ResourceID)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("resourceId '%s' could not be url-escaped: %s", input.ResourceID, err),
			StatusCode: http.StatusBadRequest,
		}
	}

	response, err := dynamoClient.GetItem(&dynamodb.GetItemInput{
		Key:       tableKey(input.ResourceID, input.PolicyID),
		TableName: &Env.ComplianceTable,
	})
	if err != nil {
		err = fmt.Errorf("dynamoClient.GetItem failed: %s", err)
		zap.L().Error("GetStatus failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	if len(response.Item) == 0 {
		return &events.APIGatewayProxyResponse{Body: "compliance entry not found", StatusCode: http.StatusNotFound}
	}

	var entry models.ComplianceEntry
	if err := dynamodbattribute.UnmarshalMap(response.Item, &entry); err != nil {
		err = fmt.Errorf("dynamodbattribute.UnmarshalMap failed: %s", err)
		zap.L().Error("GetStatus failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(&entry, http.StatusOK)
}
