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
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// ListPolicies is being deprecated. Use ListDetections and specify AnalysisType POLICY instead
func (API) ListPolicies(input *models.ListPoliciesInput) *events.APIGatewayProxyResponse {
	stdPolicyListInput(input)

	// Scan dynamo
	scanInput, err := policyScanInput(input)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	var items []tableItem
	compliance := make(map[string]complianceStatus)

	// We need to include compliance status in the response if the user asked for it
	// (or if they left the input.Fields blank, which defaults to all fields)
	statusProjection := len(input.Fields) == 0
	for _, field := range input.Fields {
		if field == "complianceStatus" {
			statusProjection = true
			break
		}
	}

	err = scanPages(scanInput, func(item tableItem) error {
		// Fetch the compliance status if we need it for the filter or projection
		if statusProjection || input.ComplianceStatus != "" {
			status, err := getComplianceStatus(item.ID) // compliance-api
			if err != nil {
				return err
			}
			compliance[item.ID] = *status
		}

		if input.ComplianceStatus != "" && input.ComplianceStatus != compliance[item.ID].Status {
			return nil // compliance status does not match filter: skip
		}

		items = append(items, item)
		return nil
	})
	if err != nil {
		zap.L().Error("failed to scan policies", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// Sort and page
	sortItems(items, input.SortBy, input.SortDir, compliance)
	var paging models.Paging
	paging, items = pageItems(items, input.Page, input.PageSize)

	// Convert to output struct
	result := models.ListPoliciesOutput{
		Policies: make([]models.Policy, 0, len(items)),
		Paging:   paging,
	}
	for _, item := range items {
		var status compliancemodels.ComplianceStatus
		if statusProjection {
			status = compliance[item.ID].Status
		}
		result.Policies = append(result.Policies, *item.Policy(status))
	}

	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}

// Set defaults and standardize input request
func stdPolicyListInput(input *models.ListPoliciesInput) {
	input.NameContains = strings.ToLower(input.NameContains)
	if input.Page == 0 {
		input.Page = defaultPage
	}
	if input.PageSize == 0 {
		input.PageSize = defaultPageSize
	}
	if input.SortBy == "" {
		input.SortBy = "id"
	}
	if input.SortDir == "" {
		input.SortDir = defaultSortDir
	}

	// TODO - fix frontend to send array inputs instead of CSV strings
	// Right now, the incoming request from a user looks like this:
	// {
	//     "resourceTypes": ["AWS.S3.Bucket,AWS.CloudFormation.Stack"],
	//     "tags": ["my,tag,filters"]
	// }
	//
	// So we split the strings here as a workaround
	if len(input.ResourceTypes) == 1 {
		input.ResourceTypes = strings.Split(input.ResourceTypes[0], ",")
	}
	if len(input.Tags) == 1 {
		input.Tags = strings.Split(input.Tags[0], ",")
	}
}

func policyScanInput(input *models.ListPoliciesInput) (*dynamodb.ScanInput, error) {
	listFilters := pythonFilters{
		CreatedBy:      input.CreatedBy,
		Enabled:        input.Enabled,
		InitialSet:     input.InitialSet,
		LastModifiedBy: input.LastModifiedBy,
		NameContains:   input.NameContains,
		Severity:       input.Severity,
		ResourceTypes:  input.ResourceTypes,
		Tags:           input.Tags,
	}

	filters := pythonListFilters(&listFilters)

	if input.HasRemediation != nil {
		if *input.HasRemediation {
			// We only want policies with a remediation specified
			filters = append(filters, expression.AttributeExists(expression.Name("autoRemediationId")))
		} else {
			// We only want policies without a remediation id
			filters = append(filters, expression.AttributeNotExists(expression.Name("autoRemediationId")))
		}
	}

	return buildScanInput([]models.DetectionType{models.TypePolicy}, input.Fields, filters...)
}
