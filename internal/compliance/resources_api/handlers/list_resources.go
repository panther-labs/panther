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
	"sort"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/api/lambda/resources/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var (
	defaultFields = []string{
		"complianceStatus",
		"deleted",
		"id",
		"integrationId",
		"integrationType",
		"lastModified",
		"type",
	}
	statusSortPriority = map[compliancemodels.ComplianceStatus]int{
		compliancemodels.StatusPass:  1,
		compliancemodels.StatusFail:  2,
		compliancemodels.StatusError: 3,
	}
)

// ListResources returns a filtered list of resources.
func (API) ListResources(input *models.ListResourcesInput) *events.APIGatewayProxyResponse {
	setListDefaults(input)

	scanInputs, err := buildListScan(input)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	zap.L().Debug("built Dynamo scan input", zap.Any("scanInputs", scanInputs))

	resources, err := listFilteredResources(scanInputs, input)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	sortResources(resources, input.SortBy, input.SortDir != "descending")
	result := pageResources(resources, input.PageSize, input.Page)
	return gatewayapi.MarshalResponse(result, http.StatusOK)
}

func setListDefaults(input *models.ListResourcesInput) {
	if len(input.Fields) == 0 {
		input.Fields = defaultFields
	}
	if input.Page == 0 {
		input.Page = 1
	}
	if input.PageSize == 0 {
		input.PageSize = 25
	}
}

func buildListScan(input *models.ListResourcesInput) ([]*dynamodb.ScanInput, error) {
	var projection expression.ProjectionBuilder
	for i, field := range input.Fields {
		if field == "complianceStatus" {
			continue
		}

		if i == 0 {
			projection = expression.NamesList(expression.Name(field))
		} else {
			projection = projection.AddNames(expression.Name(field))
		}
	}

	// Start with a dummy filter just so we have one we can add onto.
	filter := expression.AttributeExists(expression.Name("type"))

	if input.Deleted != nil {
		filter = filter.And(expression.Equal(
			expression.Name("deleted"), expression.Value(*input.Deleted)))
	}

	if input.IDContains != "" {
		filter = filter.And(expression.Contains(
			expression.Name("lowerId"), strings.ToLower(input.IDContains)))
	}

	if input.IntegrationID != "" {
		filter = filter.And(expression.Equal(
			expression.Name("integrationId"), expression.Value(input.IntegrationID)))
	}
	if input.IntegrationType != "" {
		filter = filter.And(expression.Equal(
			expression.Name("integrationType"), expression.Value(input.IntegrationType)))
	}

	if len(input.Types) > 0 {
		var typeFilter expression.ConditionBuilder
		nameExpression := expression.Name("type")

		// Chain OR filters to match one of the specified resource types
		for i, resourceType := range input.Types {
			if i == 0 {
				typeFilter = expression.Equal(nameExpression, expression.Value(resourceType))
			} else {
				typeFilter = typeFilter.Or(expression.Equal(nameExpression, expression.Value(resourceType)))
			}
		}

		filter = filter.And(typeFilter)
	}

	expr, err := expression.NewBuilder().
		WithFilter(filter).
		WithProjection(projection).
		Build()

	if err != nil {
		zap.L().Error("failed to build list query", zap.Error(err))
		return nil, err
	}

	totalSegments := env.ScanSegments
	scanInputs := make([]*dynamodb.ScanInput, 0, totalSegments)
	for i := 0; i < totalSegments; i++ {
		scanInputs = append(scanInputs, &dynamodb.ScanInput{
			ExpressionAttributeNames:  expr.Names(),
			ExpressionAttributeValues: expr.Values(),
			FilterExpression:          expr.Filter(),
			ProjectionExpression:      expr.Projection(),
			TableName:                 &env.ResourcesTable,

			Segment:       aws.Int64(int64(i)),
			TotalSegments: aws.Int64(int64(totalSegments)),
		})
	}
	return scanInputs, nil
}

// Scan the table for resources, applying additional filters before returning the results
func listFilteredResources(scanInputs []*dynamodb.ScanInput, input *models.ListResourcesInput) ([]models.Resource, error) {
	includeCompliance := false
	for _, field := range input.Fields {
		if field == "complianceStatus" {
			includeCompliance = true
			break
		}
	}
	resources, err := scanPages(scanInputs, includeCompliance, input.ComplianceStatus)

	return resources, err
}

func sortResources(resources []models.Resource, sortBy string, ascending bool) {
	if len(resources) <= 1 {
		return
	}

	switch sortBy {
	case "complianceStatus":
		// The status cache has already been populated, we can access it directly
		resourceStatus := complianceCache.Resources
		sort.Slice(resources, func(i, j int) bool {
			left, right := resources[i], resources[j]
			if left.ComplianceStatus != right.ComplianceStatus {
				// Group first by compliance status
				if ascending {
					return statusSortPriority[left.ComplianceStatus] < statusSortPriority[right.ComplianceStatus]
				}
				return statusSortPriority[left.ComplianceStatus] > statusSortPriority[right.ComplianceStatus]
			}

			// Same pass/fail status: use sort index for ERROR and FAIL
			// This will sort by "top failing": the most failures in order of severity
			if left.ComplianceStatus == compliancemodels.StatusError || left.ComplianceStatus == compliancemodels.StatusFail {
				leftIndex := resourceStatus[left.ID].SortIndex
				rightIndex := resourceStatus[right.ID].SortIndex
				if ascending {
					return leftIndex > rightIndex
				}
				return leftIndex < rightIndex
			}

			// Default: sort by ID
			if ascending {
				return left.ID < right.ID
			}
			return left.ID > right.ID
		})

	case "lastModified":
		sort.Slice(resources, func(i, j int) bool {
			left, right := resources[i], resources[j]

			if left.LastModified != right.LastModified {
				if ascending {
					return left.LastModified.Before(right.LastModified)
				}
				return left.LastModified.After(right.LastModified)
			}

			// Same timestamp: sort by ID
			if ascending {
				return left.ID < right.ID
			}
			return left.ID > right.ID
		})

	case "type":
		sort.Slice(resources, func(i, j int) bool {
			left, right := resources[i], resources[j]

			if left.Type != right.Type {
				if ascending {
					return left.Type < right.Type
				}
				return left.Type > right.Type
			}

			// Same type: sort by ID
			if ascending {
				return left.ID < right.ID
			}
			return left.ID > right.ID
		})

	default: // sort by id
		sort.Slice(resources, func(i, j int) bool {
			left, right := resources[i], resources[j]
			if ascending {
				return left.ID < right.ID
			}
			return left.ID > right.ID
		})
	}
}

func pageResources(resources []models.Resource, pageSize, page int) *models.ListResourcesOutput {
	if len(resources) == 0 {
		// Empty results - there are no pages
		return &models.ListResourcesOutput{
			Resources: []models.Resource{},
		}
	}

	totalPages := len(resources) / pageSize
	if len(resources)%pageSize > 0 {
		totalPages++ // Add one more to page count if there is an incomplete page at the end
	}

	paging := models.Paging{
		ThisPage:   page,
		TotalItems: len(resources),
		TotalPages: totalPages,
	}

	// Truncate policies to just the requested page
	lowerBound := intMin((page-1)*pageSize, len(resources))
	upperBound := intMin(page*pageSize, len(resources))
	return &models.ListResourcesOutput{Paging: paging, Resources: resources[lowerBound:upperBound]}
}

func intMin(x, y int) int {
	if x < y {
		return x
	}
	return y
}
