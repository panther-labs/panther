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
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// DescribeResource returns all pass/fail information needed for the resource overview page.
func (API) DescribeResource(input *models.DescribeResourceInput) *events.APIGatewayProxyResponse {
	var err error
	input.ResourceID, err = url.QueryUnescape(input.ResourceID)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("resourceId '%s' could not be url-escaped: %s", input.ResourceID, err),
			StatusCode: http.StatusBadRequest,
		}
	}

	queryInput, err := buildDescribeResourceQuery(input.ResourceID)
	if err != nil {
		zap.L().Error("DescribeResource failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	detail, err := policyResourceDetail(queryInput, input.Page, input.PageSize, input.Severity, input.Status, input.Suppressed)
	if err != nil {
		zap.L().Error("DescribeResource failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(detail, http.StatusOK)
}

func buildDescribeResourceQuery(resourceID string) (*dynamodb.QueryInput, error) {
	keyCondition := expression.Key("resourceId").Equal(expression.Value(resourceID))
	// We can't do any additional filtering here because we need to include global totals
	expr, err := expression.NewBuilder().WithKeyCondition(keyCondition).Build()
	if err != nil {
		return nil, fmt.Errorf("expression.Build failed: %s", err)
	}

	return &dynamodb.QueryInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		KeyConditionExpression:    expr.KeyCondition(),
		TableName:                 &Env.ComplianceTable,
	}, nil
}
