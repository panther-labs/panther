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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// DescribeOrg returns pass/fail counts for every policy or resource in a customer account.
func (API) DescribeOrg(input *models.DescribeOrgInput) *events.APIGatewayProxyResponse {
	queryInput, err := buildDescribeOrgScan()
	if err != nil {
		zap.L().Error("DescribeOrg failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	var result models.DescribeOrgOutput
	if input.Type == "policy" {
		result.Policies, err = listPolicies(queryInput)
	} else {
		result.Resources, err = listResources(queryInput)
	}
	if err != nil {
		zap.L().Error("DescribeOrg failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}

func buildDescribeOrgScan() (*dynamodb.ScanInput, error) {
	filter := expression.Equal(expression.Name("suppressed"), expression.Value(false))
	projection := expression.NamesList(
		expression.Name("policyId"),
		expression.Name("policySeverity"),
		expression.Name("resourceId"),
		expression.Name("status"),
	)

	expr, err := expression.NewBuilder().
		WithFilter(filter).
		WithProjection(projection).
		Build()
	if err != nil {
		return nil, fmt.Errorf("dynamo expression.Build failed: %s", err)
	}

	return &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &Env.ComplianceTable,
	}, nil
}

// List policies, sort by top failing
func listPolicies(input *dynamodb.ScanInput) ([]models.ItemSummary, error) {
	// Fetch all policies from Dynamo
	policyMap, _, err := scanGroupByID(input, true, false)
	if err != nil {
		return nil, err
	}

	// Convert to a slice and sort by top failing
	policySlice := make([]models.PolicySummary, 0, len(policyMap))
	for _, policy := range policyMap {
		policySlice = append(policySlice, *policy)
	}
	sortPoliciesByTopFailing(policySlice)

	// Convert to final ItemSummary
	result := make([]models.ItemSummary, len(policySlice))
	for i, policy := range policySlice {
		result[i] = models.ItemSummary{
			ID:     policy.ID,
			Status: countToStatus(policy.Count),
		}
	}

	return result, nil
}

// List resources, sort by top failing
func listResources(input *dynamodb.ScanInput) ([]models.ItemSummary, error) {
	// Fetch all resources from Dynamo
	_, resourceMap, err := scanGroupByID(input, false, true)
	if err != nil {
		return nil, err
	}

	// Convert to a slice and sort by top failing
	resourceSlice := make([]models.ResourceSummary, 0, len(resourceMap))
	for _, resource := range resourceMap {
		resourceSlice = append(resourceSlice, *resource)
	}
	sortResourcesByTopFailing(resourceSlice)

	// Convert to final ItemSummary
	result := make([]models.ItemSummary, len(resourceSlice))
	for i, resource := range resourceSlice {
		result[i] = models.ItemSummary{
			ID:     resource.ID,
			Status: countBySeverityToStatus(&resource.Count),
		}
	}

	return result, nil
}
