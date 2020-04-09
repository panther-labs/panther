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
	"errors"
	"net/http"
	"net/url"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/resources/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// GetResource retrieves a single resource from the Dynamo table.
func GetResource(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	resourceID, err := parseGetResource(request)
	if err != nil {
		return badRequest(err)
	}

	response, err := dynamoClient.GetItem(&dynamodb.GetItemInput{
		Key:       tableKey(resourceID),
		TableName: &env.ResourcesTable,
	})
	if err != nil {
		zap.L().Error("dynamoClient.GetItem failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	if len(response.Item) == 0 {
		zap.L().Debug("could not find resource", zap.String("resourceID", string(resourceID)))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusNotFound}
	}

	var item resourceItem
	if err := dynamodbattribute.UnmarshalMap(response.Item, &item); err != nil {
		zap.L().Error("dynamodbattribute.UnmarshalMap failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	status, err := getComplianceStatus(resourceID)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(item.Resource(status.Status), http.StatusOK)
}

// API gateway doesn't do advanced validation of query parameters, but we can do it here.
func parseGetResource(request *events.APIGatewayProxyRequest) (resourceID models.ResourceID, err error) {
	escaped, err := url.QueryUnescape(request.QueryStringParameters["resourceId"])
	if err != nil {
		err = errors.New("invalid resourceId: " + err.Error())
		return
	}

	resourceID = models.ResourceID(escaped)
	if err = resourceID.Validate(nil); err != nil {
		err = errors.New("invalid resourceId: " + err.Error())
	}
	return
}
