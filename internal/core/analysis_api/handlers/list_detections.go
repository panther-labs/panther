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
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

func (API) ListDetections(input *models.ListDetectionsInput) *events.APIGatewayProxyResponse {
	items, compliance, err := handleListItems(input)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}
	// Sort and page
	sortItems(items, input.SortBy, input.SortDir, nil)
	var paging models.Paging
	paging, items = pageItems(items, input.Page, input.PageSize)
	// Convert to output struct
	result := models.ListDetectionsOutput{
		Detections: make([]models.Detection, 0, len(items)),
		Paging:     paging,
	}
	for _, item := range items {
		status := compliance[item.ID].Status
		result.Detections = append(result.Detections, *item.Detection(status))
	}

	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}

func handleListItems(input *models.ListDetectionsInput) ([]tableItem, map[string]complianceStatus, error) {
	projectComplianceStatus := stdDetectionListInput(input)

	// Scan dynamo
	scanInput, err := detectionScanInput(input)
	if err != nil {
		return nil, nil, err
	}

	var items []tableItem
	compliance := make(map[string]complianceStatus)

	err = scanPages(scanInput, func(item tableItem) error {
		// Fetch the compliance status if we need it for the filter or projection
		if item.Type == models.TypePolicy && (projectComplianceStatus || input.ComplianceStatus != "") {
			status, err := getComplianceStatus(item.ID)
			if err != nil {
				return err
			}
			compliance[item.ID] = *status
		}

		// If the ComplianceStatus filter is set, we know we already filtered to just policies
		if input.ComplianceStatus != "" && input.ComplianceStatus != compliance[item.ID].Status {
			return nil // compliance status does not match filter: skip
		}

		items = append(items, item)
		return nil
	})
	if err != nil {
		zap.L().Error("failed to scan detections", zap.Error(err))
		return nil, nil, err
	}
	for _, item := range items {
		status := compliance[item.ID].Status
		item.Detection(status)
	}
	return items, compliance, nil
}

// Set defaults and standardize input request
func stdDetectionListInput(input *models.ListDetectionsInput) bool {
	input.NameContains = strings.ToLower(input.NameContains)
	if input.Page == 0 {
		input.Page = defaultPage
	}
	if input.PageSize == 0 {
		input.PageSize = defaultPageSize
	}
	if input.SortBy == "" {
		input.SortBy = "displayName"
	}
	// If we are going to sort by displayName, we must include lowerId and lowerDisplayName in the
	// projection. If Fields is empty they're included already.
	if input.SortBy == "displayName" && len(input.Fields) > 0 {
		input.Fields = append(input.Fields, "lowerId", "lowerDisplayName")
	}
	// Similar idea as displayName
	if input.SortBy == "id" && len(input.Fields) > 0 {
		input.Fields = append(input.Fields, "lowerId")
	}
	if input.SortDir == "" {
		input.SortDir = defaultSortDir
	}
	if len(input.AnalysisTypes) == 0 {
		input.AnalysisTypes = []models.DetectionType{models.TypePolicy, models.TypeRule}
	}
	// If a compliance status was specified, we can only query policies.
	// This is a unique field because we look it up from another table. For other fields (such as
	// suppressions for policies or dedup period for rules) we don't need this logic because if the
	// user filters on this field it will automatically exclude everything of the wrong type.
	if input.ComplianceStatus != "" || input.HasRemediation != nil {
		input.AnalysisTypes = []models.DetectionType{models.TypePolicy}
	}

	// If we need to filter or project based on complianceStatus, we must ensure that id and type are
	// also within the projection. If fields is empty they're already included and we can just return.
	if len(input.Fields) == 0 {
		return true
	}

	idPresent, typePresent, statusProjection := false, false, false
	for _, field := range input.Fields {
		if field == "complianceStatus" {
			statusProjection = true
		}
		if field == "id" {
			idPresent = true
		}
		if field == "type" {
			typePresent = true
		}
		if idPresent && typePresent && statusProjection {
			break
		}
	}
	if statusProjection || input.ComplianceStatus != "" {
		if !idPresent {
			input.Fields = append(input.Fields, "id")
		}
		if !typePresent {
			input.Fields = append(input.Fields, "type")
		}
	}

	return statusProjection
}

func detectionScanInput(input *models.ListDetectionsInput) (*dynamodb.ScanInput, error) {
	listFilters := pythonFilters{
		CreatedBy:      input.CreatedBy,
		Enabled:        input.Enabled,
		IDs:            input.IDs,
		InitialSet:     input.InitialSet,
		LastModifiedBy: input.LastModifiedBy,
		NameContains:   input.NameContains,
		Severity:       input.Severity,
		ResourceTypes:  input.ResourceTypes,
		Tags:           input.Tags,
	}
	if input.LogTypes != nil {
		listFilters.ResourceTypes = append(listFilters.ResourceTypes, input.LogTypes...)
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

	return buildScanInput(input.AnalysisTypes, input.Fields, filters...)
}
