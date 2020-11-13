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

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

func (API) ListPolicies(input *models.ListPoliciesInput) *events.APIGatewayProxyResponse {
	if err := stdPolicyListInput(input); err != nil {
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusBadRequest}
	}

	// Scan dynamo
	scanInput, err := policyScanInput(input)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	var items []tableItem
	compliance := make(map[string]complianceStatus)

	err = scanPages(scanInput, func(item tableItem) error {
		// Filter by compliance status: this information is in the compliance-api, not this table
		if input.ComplianceStatus != "" {
			status, err := getComplianceStatus(item.ID)
			if err != nil {
				return err
			}
			if input.ComplianceStatus != status.Status {
				return nil // compliance status does not match filter: skip
			}
			compliance[item.ID] = *status
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
		result.Policies = append(result.Policies, *item.Policy(compliance[item.ID].Status))
	}

	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}

// Set defaults and standardize input request
func stdPolicyListInput(input *models.ListPoliciesInput) error {
	if input.Page == 0 {
		input.Page = defaultPage
	}
	if input.PageSize == 0 {
		input.PageSize = defaultPageSize
	}
	if input.SortBy == "" {
		input.SortBy = defaultSortBy
	}
	if input.SortDir == "" {
		input.SortDir = defaultSortDir
	}

	// TODO - frontend no longer needs to query escape this
	var err error
	if input.NameContains, err = url.QueryUnescape(input.NameContains); err != nil {
		return fmt.Errorf("invalid nameContains: " + err.Error())
	}
	return nil
}

func policyScanInput(input *models.ListPoliciesInput) (*dynamodb.ScanInput, error) {
	filters := pythonListFilters(input.Enabled, input.NameContains, string(input.Severity), input.ResourceTypes, input.Tags)

	if input.HasRemediation != nil {
		if *input.HasRemediation {
			// We only want policies with a remediation specified
			filters = append(filters, expression.AttributeExists(expression.Name("autoRemediationId")))
		} else {
			// We only want policies without a remediation id
			filters = append(filters, expression.AttributeNotExists(expression.Name("autoRemediationId")))
		}
	}

	return buildScanInput(models.TypePolicy, input.Fields, filters...)
}
