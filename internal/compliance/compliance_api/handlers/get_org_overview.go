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

// GetOrgOverview returns all the pass/fail information for the Panther overview dashboard.
func (API) GetOrgOverview(input *models.GetOrgOverviewInput) *events.APIGatewayProxyResponse {
	if input.LimitTopFailing == 0 {
		input.LimitTopFailing = models.DefaultLimitTopFailing
	}

	queryInput, err := buildGetOrgOverviewQuery()
	if err != nil {
		zap.L().Error("GetOrgOverview failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	policies, resources, err := scanGroupByID(queryInput, true, true)
	if err != nil {
		zap.L().Error("GetOrgOverview failed", zap.Error(err))
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	return gatewayapi.MarshalResponse(buildOverview(policies, resources, input.LimitTopFailing), http.StatusOK)
}

func buildGetOrgOverviewQuery() (*dynamodb.ScanInput, error) {
	filter := expression.Equal(expression.Name("suppressed"), expression.Value(false))

	expr, err := expression.NewBuilder().WithFilter(filter).Build()
	if err != nil {
		return nil, fmt.Errorf("expression.Build failed: %s", err)
	}

	return &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		TableName:                 &Env.ComplianceTable,
	}, nil
}

func buildOverview(policies policyMap, resources resourceMap, limitTopFailing int) *models.OrgSummary {
	// Count policies by severity and record failed policies
	var appliedPolicies models.StatusCountBySeverity
	var failedPolicies []models.PolicySummary
	for _, policy := range policies {
		status := countToStatus(policy.Count)
		updateStatusCountBySeverity(&appliedPolicies, policy.Severity, status)
		if status != models.StatusPass {
			failedPolicies = append(failedPolicies, *policy)
		}
	}

	// Sort and truncate failed policies
	sortPoliciesByTopFailing(failedPolicies)
	if len(failedPolicies) > limitTopFailing {
		failedPolicies = failedPolicies[:limitTopFailing]
	}

	// Count resources by type and record failed resources
	resourcesByType := make(map[string]models.StatusCount, 100)
	failedResources := make([]models.ResourceSummary, 0, len(resources)/2)
	for _, resource := range resources {
		count := resourcesByType[resource.Type]
		status := countBySeverityToStatus(&resource.Count)
		updateStatusCount(&count, status)
		if status != models.StatusPass {
			failedResources = append(failedResources, *resource)
		}
		resourcesByType[resource.Type] = count
	}

	// Convert resourcesByType into appropriate struct
	scannedResources := models.ScannedResources{
		ByType: make([]models.ResourceOfType, 0, len(resourcesByType)),
	}
	for resourceType, count := range resourcesByType {
		entry := models.ResourceOfType{Count: count, Type: resourceType}
		scannedResources.ByType = append(scannedResources.ByType, entry)
	}

	// Sort and truncate failing resources
	sortResourcesByTopFailing(failedResources)
	if len(failedResources) > limitTopFailing {
		failedResources = failedResources[:limitTopFailing]
	}

	return &models.OrgSummary{
		AppliedPolicies:     appliedPolicies,
		ScannedResources:    scannedResources,
		TopFailingPolicies:  failedPolicies,
		TopFailingResources: failedResources,
	}
}
