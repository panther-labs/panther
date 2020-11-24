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

	"github.com/aws/aws-lambda-go/events"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

func (API) ListDataModels(input *models.ListDataModelsInput) *events.APIGatewayProxyResponse {
	// Set defaults
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

	// Scan dynamo
	scanInput, err := buildScanInput(models.TypeDataModel, nil)
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
		zap.L().Error("failed to scan data models", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// Sort and page
	sortItems(items, "id", input.SortDir, nil)
	var paging models.Paging
	paging, items = pageItems(items, input.Page, input.PageSize)

	// Convert to output struct
	result := models.ListDataModelsOutput{
		Models: make([]models.DataModel, 0, len(items)),
		Paging: paging,
	}
	for _, item := range items {
		result.Models = append(result.Models, *item.DataModel())
	}

	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}
