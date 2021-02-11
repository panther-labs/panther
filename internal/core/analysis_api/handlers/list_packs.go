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
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

func (API) EnumeratePack(input *models.EnumeratePackInput) *events.APIGatewayProxyResponse {
	if input.Page == 0 {
		input.Page = defaultPage
	}
	if input.PageSize == 0 {
		input.PageSize = defaultPageSize
	}
	var pack *packTableItem
	pack, err := dynamoGetPack(input.ID, false)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Internal error finding %s (%s)", input.ID, models.TypePack),
			StatusCode: http.StatusInternalServerError,
		}
	}
	if pack == nil {
		return &events.APIGatewayProxyResponse{
			Body:       fmt.Sprintf("Cannot find %s (%s)", input.ID, models.TypePack),
			StatusCode: http.StatusNotFound,
		}
	}
	// Convert pack definition to a list detection option
	listDetectionInput := getListOptions(input, pack.PackDefinition)
	items, compliance, err := handleListItems(listDetectionInput)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}
	// Page
	var paging models.Paging
	paging, items = pageItems(items, input.Page, input.PageSize)
	// Convert to output struct
	result := models.EnumeratePackOutput{
		Detections: make([]models.Detection, 0, pack.PackTypes[models.TypePolicy]+pack.PackTypes[models.TypeRule]),
		Globals:    make([]models.Global, 0, pack.PackTypes[models.TypeGlobal]),
		Models:     make([]models.DataModel, 0, pack.PackTypes[models.TypeDataModel]),
		Paging:     paging,
	}
	for _, item := range items {
		switch item.Type {
		case models.TypePolicy, models.TypeRule:
			status := compliance[item.ID].Status
			result.Detections = append(result.Detections, *item.Detection(status))
		case models.TypeGlobal:
			result.Globals = append(result.Globals, *item.Global())
		case models.TypeDataModel:
			result.Models = append(result.Models, *item.DataModel())
		default:
			zap.L().Warn("attempting to add unknown analysis type to pack enumeration", zap.String("analysisType", string(item.Type)))
		}
	}
	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}

func (API) ListPacks(input *models.ListPacksInput) *events.APIGatewayProxyResponse {
	// Standardize input
	input.NameContains = strings.ToLower(input.NameContains)
	if input.Page == 0 {
		input.Page = defaultPage
	}
	if input.PageSize == 0 {
		input.PageSize = defaultPageSize
	}

	// Scan dynamo
	scanInput, err := scanPackInput(input)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	items, err := getPackItems(scanInput)
	if err != nil {
		zap.L().Error("failed to scan packs", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// Sorting not supported in this version
	// Page
	var paging models.Paging
	paging, items = pagePackItems(items, input.Page, input.PageSize)

	// Convert to output struct
	result := models.ListPacksOutput{
		Packs:  make([]models.Pack, 0, len(items)),
		Paging: paging,
	}
	for _, item := range items {
		result.Packs = append(result.Packs, *item.Pack())
	}

	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}

func getListOptions(input *models.EnumeratePackInput, definition models.PackDefinition) *models.ListDetectionsInput {
	// Currently, we only support defining IDs, this can be extended
	// in the future to convert other defitions into a proper list option
	listInput := models.ListDetectionsInput{
		IDs: definition.IDs,
	}
	// Packs can contain any "detection" types
	listInput.AnalysisTypes = []models.DetectionType{models.TypeDataModel, models.TypeGlobal, models.TypePolicy, models.TypeRule}
	// then populate the other standard fields
	listInput.Fields = input.Fields
	listInput.PageSize = input.PageSize
	listInput.Page = input.Page
	return &listInput
}

func scanPackInput(input *models.ListPacksInput) (*dynamodb.ScanInput, error) {
	var filters []expression.ConditionBuilder

	if input.Enabled != nil {
		filters = append(filters, expression.Equal(
			expression.Name("enabled"), expression.Value(*input.Enabled)))
	}

	if input.PackVersion.SemVer != "" {
		filters = append(filters, expression.Equal(expression.Name("packVersion"),
			expression.Value(input.PackVersion)))
	}

	if input.NameContains != "" {
		filters = append(filters, expression.Contains(expression.Name("lowerId"), input.NameContains).
			Or(expression.Contains(expression.Name("lowerDisplayName"), input.NameContains)))
	}

	if input.UpdateAvailable != nil {
		filters = append(filters, expression.Equal(expression.Name("updateAvailable"), expression.Value(*input.UpdateAvailable)))
	}

	return buildTableScanInput(env.PackTable, []models.DetectionType{models.TypePack}, input.Fields, filters...)
}

func getPackItems(scanInput *dynamodb.ScanInput) ([]*packTableItem, error) {
	var items []*packTableItem
	err := scanPackPages(scanInput, func(item packTableItem) error {
		items = append(items, &item)
		return nil
	})
	return items, err
}

// Truncate list of items to the requested page
func pagePackItems(items []*packTableItem, page, pageSize int) (models.Paging, []*packTableItem) {
	if len(items) == 0 {
		return models.Paging{}, nil
	}

	totalPages := len(items) / pageSize
	if len(items)%pageSize > 0 {
		totalPages++ // Add one more to page count if there is an incomplete page at the end
	}

	paging := models.Paging{
		ThisPage:   page,
		TotalItems: len(items),
		TotalPages: totalPages,
	}

	// Truncate to just the requested page
	lowerBound := intMin((page-1)*pageSize, len(items))
	upperBound := intMin(page*pageSize, len(items))
	return paging, items[lowerBound:upperBound]
}
