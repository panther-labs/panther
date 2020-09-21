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

type describePolicyParams struct {
	pageParams
	PolicyID models.PolicyID
}

// DescribePolicy returns all pass/fail information needed for the policy overview page.
func DescribePolicy(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	params, err := parseDescribePolicy(request)
	if err != nil {
		return badRequest(err)
	}

	input, err := buildDescribePolicyQuery(params.PolicyID)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	detail, err := policyResourceDetail(input, &params.pageParams, "")
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(detail, http.StatusOK)
}

func parseDescribePolicy(request *events.APIGatewayProxyRequest) (*describePolicyParams, error) {
	pageParams, err := parsePageParams(request)
	if err != nil {
		return nil, err
	}

	policyID, err := url.QueryUnescape(request.QueryStringParameters["policyId"])
	if err != nil {
		return nil, errors.New("invalid policyId: " + err.Error())
	}

	result := describePolicyParams{pageParams: *pageParams, PolicyID: models.PolicyID(policyID)}

	if err = result.PolicyID.Validate(nil); err != nil {
		return nil, errors.New("invalid policyId: " + err.Error())
	}

	return &result, nil
}

func buildDescribePolicyQuery(policyID models.PolicyID) (*dynamodb.QueryInput, error) {
	keyCondition := expression.Key("policyId").Equal(expression.Value(policyID))

	// We can't do any additional filtering here because we need to include global totals
	expr, err := expression.NewBuilder().WithKeyCondition(keyCondition).Build()
	if err != nil {
		zap.L().Error("expression.Build failed", zap.Error(err))
		return nil, err
	}

	return &dynamodb.QueryInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		IndexName:                 &Env.IndexName,
		KeyConditionExpression:    expr.KeyCondition(),
		TableName:                 &Env.ComplianceTable,
	}, nil
}
