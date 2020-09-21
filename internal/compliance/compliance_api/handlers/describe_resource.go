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
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"
	"github.com/panther-labs/panther/api/gateway/compliance/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

type describeResourceParams struct {
	pageParams
	ResourceID models.ResourceID
	Severity   models.PolicySeverity
}

// DescribeResource returns all pass/fail information needed for the resource overview page.
func DescribeResource(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	params, err := parseDescribeResource(request)
	if err != nil {
		return badRequest(err)
	}

	input, err := buildDescribeResourceQuery(params.ResourceID)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	detail, err := policyResourceDetail(input, &params.pageParams, params.Severity)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(detail, http.StatusOK)
}

func parseDescribeResource(request *events.APIGatewayProxyRequest) (*describeResourceParams, error) {
	pageParams, err := parsePageParams(request)
	if err != nil {
		return nil, err
	}

	resourceID, err := url.QueryUnescape(request.QueryStringParameters["resourceId"])
	if err != nil {
		return nil, errors.New("invalid resourceId: " + err.Error())
	}

	resourceModel := models.ResourceID(resourceID)
	if err = resourceModel.Validate(nil); err != nil {
		return nil, errors.New("invalid resourceId: " + err.Error())
	}

	result := describeResourceParams{
		pageParams: *pageParams,
		ResourceID: resourceModel,
		Severity:   models.PolicySeverity(request.QueryStringParameters["severity"]),
	}

	if result.Severity != "" {
		if err = result.Severity.Validate(nil); err != nil {
			return nil, errors.New("invalid severity: " + err.Error())
		}
	}

	return &result, nil
}

func buildDescribeResourceQuery(resourceID models.ResourceID) (*dynamodb.QueryInput, error) {
	keyCondition := expression.Key("resourceId").Equal(expression.Value(resourceID))
	// We can't do any additional filtering here because we need to include global totals
	expr, err := expression.NewBuilder().WithKeyCondition(keyCondition).Build()
	if err != nil {
		zap.L().Error("expression.Build failed", zap.Error(err))
		return nil, err
	}

	return &dynamodb.QueryInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		KeyConditionExpression:    expr.KeyCondition(),
		TableName:                 &Env.ComplianceTable,
	}, nil
}
