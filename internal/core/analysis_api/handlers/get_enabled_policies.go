package handlers

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
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// GetEnabledPolicies fetches all enabled policies from an organization for backend processing.
func GetEnabledPolicies(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	ruleType := parseGetEnabled(request)

	scanInput, err := buildEnabledScan(ruleType)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	policies := make([]*models.EnabledPolicy, 0, 100)
	err = scanPages(scanInput, func(policy *tableItem) error {
		policies = append(policies, &models.EnabledPolicy{
			Body:          policy.Body,
			ID:            policy.ID,
			ResourceTypes: policy.ResourceTypes,
			Severity:      policy.Severity,
			Suppressions:  policy.Suppressions,
			VersionID:     policy.VersionID,
		})
		return nil
	})
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(&models.EnabledPolicies{Policies: policies}, http.StatusOK)
}

func parseGetEnabled(request *events.APIGatewayProxyRequest) string {
	ruleType := strings.ToUpper(request.QueryStringParameters["type"])
	if ruleType == "" {
		ruleType = typePolicy // default to loading policies
	}

	return ruleType
}

func buildEnabledScan(ruleType string) (*dynamodb.ScanInput, error) {
	filter := expression.Equal(expression.Name("enabled"), expression.Value(true))
	filter = filter.And(expression.Equal(expression.Name("type"), expression.Value(ruleType)))
	projection := expression.NamesList(
		// does not include unit tests, last modified, org id, reference, tags, etc
		expression.Name("body"),
		expression.Name("id"),
		expression.Name("resourceTypes"),
		expression.Name("severity"),
		expression.Name("suppressions"),
		expression.Name("versionId"),
	)

	expr, err := expression.NewBuilder().
		WithFilter(filter).
		WithProjection(projection).
		Build()

	if err != nil {
		zap.L().Error("failed to build enabled query", zap.Error(err))
		return nil, err
	}

	return &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &env.Table,
	}, nil
}
