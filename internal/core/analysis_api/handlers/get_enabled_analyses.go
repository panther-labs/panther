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
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// GetEnabledAnalyses fetches all enabled policies or rules.
func GetEnabledAnalyses(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	analysisType, err := parseAnalysisType(request)
	if err != nil {
		return badRequest(err)
	}

	scanInput, err := buildEnabledScan(analysisType)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	policies := make([]*models.EnabledPolicy, 0, 100)
	err = scanPages(scanInput, func(policy *tableItem) error {
		policies = append(policies, &models.EnabledPolicy{
			Body:               policy.Body,
			DedupPeriodMinutes: policy.DedupPeriodMinutes,
			ID:                 policy.ID,
			Mappings:           policy.Mappings,
			OutputIds:          policy.OutputIds,
			Reports:            policy.Reports,
			ResourceTypes:      policy.ResourceTypes,
			Severity:           policy.Severity,
			Suppressions:       policy.Suppressions,
			Tags:               policy.Tags,
			VersionID:          policy.VersionID,
		})
		return nil
	})
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(&models.EnabledPolicies{Policies: policies}, http.StatusOK)
}

func parseAnalysisType(request *events.APIGatewayProxyRequest) (string, error) {
	analysisType := strings.ToUpper(request.QueryStringParameters["type"])
	if analysisType == "" {
		return "", errors.New("'type' is a required parameter")
	}

	return analysisType, nil
}

func buildEnabledScan(ruleType string) (*dynamodb.ScanInput, error) {
	filter := expression.Equal(expression.Name("enabled"), expression.Value(true))
	filter = filter.And(expression.Equal(expression.Name("type"), expression.Value(ruleType)))
	projection := expression.NamesList(
		// does not include unit tests, last modified, reference, etc
		expression.Name("body"),
		expression.Name("dedupPeriodMinutes"),
		expression.Name("id"),
		expression.Name("mappings"),
		expression.Name("outputIds"),
		expression.Name("reports"),
		expression.Name("resourceTypes"),
		expression.Name("severity"),
		expression.Name("suppressions"),
		expression.Name("tags"),
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
