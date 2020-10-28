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

// DescribePolicy returns all pass/fail information needed for the policy overview page.
func (API) DescribePolicy(input *models.DescribePolicyInput) *events.APIGatewayProxyResponse {
	var err error
	input.PolicyID, err = url.QueryUnescape(input.PolicyID)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("policyId '%s' could not be url-escaped: %s", input.PolicyID, err),
			StatusCode: http.StatusBadRequest,
		}
	}

	queryInput, err := buildDescribePolicyQuery(input.PolicyID)
	if err != nil {
		zap.L().Error("DescribePolicy failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	detail, err := policyResourceDetail(queryInput, input.Page, input.PageSize, "", input.Status, input.Suppressed)
	if err != nil {
		zap.L().Error("DescribePolicy failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(detail, http.StatusOK)
}

func buildDescribePolicyQuery(policyID string) (*dynamodb.QueryInput, error) {
	keyCondition := expression.Key("policyId").Equal(expression.Value(policyID))

	// We can't do any additional filtering here because we need to include global totals
	expr, err := expression.NewBuilder().WithKeyCondition(keyCondition).Build()
	if err != nil {
		return nil, fmt.Errorf("expression.Build failed: %s", err)
	}

	return &dynamodb.QueryInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		IndexName:                 &Env.IndexName,
		KeyConditionExpression:    expr.KeyCondition(),
		TableName:                 &Env.ComplianceTable,
	}, nil
}
