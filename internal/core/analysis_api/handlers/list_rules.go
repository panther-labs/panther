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
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

func (API) ListRules(input *models.ListRulesInput) *events.APIGatewayProxyResponse {
	if err := stdRuleListInput(input); err != nil {
		return &events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: http.StatusBadRequest}
	}

	// Scan dynamo
	scanInput, err := ruleScanInput(input)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	var items []tableItem
	err = scanPages(scanInput, func(item tableItem) error {
		items = append(items, item)
		return nil
	})
	if err != nil {
		zap.L().Error("failed to scan rules", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// Sort and page
	sortItems(items, input.SortBy, input.SortDir, nil)
	var paging models.Paging
	paging, items = pageItems(items, input.Page, input.PageSize)

	// Convert to output struct
	result := models.ListRulesOutput{
		Rules:  make([]models.Rule, 0, len(items)),
		Paging: paging,
	}
	for _, item := range items {
		result.Rules = append(result.Rules, *item.Rule())
	}

	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}

// Set defaults and standardize input request
func stdRuleListInput(input *models.ListRulesInput) error {
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

func ruleScanInput(input *models.ListRulesInput) (*dynamodb.ScanInput, error) {
	filters := pythonListFilters(input.Enabled, input.NameContains, string(input.Severity), input.LogTypes, input.Tags)
	return buildScanInput(models.TypeRule, input.Fields, filters...)
}
