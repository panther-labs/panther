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
	"net/url"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/resources/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// GetResource retrieves a single resource from the Dynamo table.
func (API) GetResource(input *models.GetResourceInput) *events.APIGatewayProxyResponse {
	// TODO - remove url-encoding from frontend; it's no longer necessary with API gateway removed
	var err error
	input.ID, err = url.QueryUnescape(input.ID)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest, Body: err.Error()}
	}

	response, err := dynamoClient.GetItem(&dynamodb.GetItemInput{
		Key:       tableKey(input.ID),
		TableName: &env.ResourcesTable,
	})
	if err != nil {
		zap.L().Error("dynamoClient.GetItem failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if len(response.Item) == 0 {
		zap.L().Debug("could not find resource", zap.String("resourceID", input.ID))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
	}

	var item resourceItem
	if err := dynamodbattribute.UnmarshalMap(response.Item, &item); err != nil {
		zap.L().Error("dynamodbattribute.UnmarshalMap failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	status, err := getComplianceStatus(input.ID)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	result := item.Resource(status.Status)
	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}
