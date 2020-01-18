package handlers

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/go-openapi/strfmt"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/gateway/resources/client/operations"
	"github.com/panther-labs/panther/api/gateway/resources/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var (
	validSortFields = map[string]bool{
		"complianceStatus": true,
		"id":               true,
		"lastModified":     true,
		"type":             true,
	}

	// We can't use defaults from swagger here: https://github.com/go-swagger/go-swagger/issues/2096
	defaultFields = []string{
		"complianceStatus",
		"deleted",
		"id",
		"integrationId",
		"integrationType",
		"lastModified",
		"type",
	}
	statusSortPriority = map[models.ComplianceStatus]int{
		models.ComplianceStatusPASS:  1,
		models.ComplianceStatusFAIL:  2,
		models.ComplianceStatusERROR: 3,
	}
)

// ListResources returns a filtered list of resources.
func ListResources(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	params, err := parseListResources(request)
	if err != nil {
		return badRequest(err)
	}

	scanInput, err := buildListScan(params)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	resources, err := listFilteredResources(scanInput, params)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	sortResources(resources, aws.StringValue(params.SortBy), aws.StringValue(params.SortDir) != "descending")
	result := pageResources(resources, int(*params.PageSize), int(*params.Page))
	return gatewayapi.MarshalResponse(result, http.StatusOK)
}

func parseListResources(request *events.APIGatewayProxyRequest) (*operations.ListResourcesParams, error) {
	result := operations.NewListResourcesParams() // initialize with default values

	// ***** Filtering *****
	if status := request.QueryStringParameters["complianceStatus"]; status != "" {
		if err := models.ComplianceStatus(status).Validate(nil); err != nil {
			return nil, errors.New("invalid complianceStatus: " + err.Error())
		}
		result.ComplianceStatus = aws.String(status)
	}

	if deleted := request.QueryStringParameters["deleted"]; deleted != "" {
		val, err := strconv.ParseBool(deleted)
		if err != nil {
			return nil, errors.New("invalid deleted: " + err.Error())
		}
		result.Deleted = aws.Bool(val)
	}

	if contains := request.QueryStringParameters["idContains"]; contains != "" {
		val, err := url.QueryUnescape(contains)
		if err != nil {
			return nil, errors.New("invalid idContains: " + err.Error())
		}
		result.IDContains = aws.String(strings.ToLower(val))
	}

	if integrationID := request.QueryStringParameters["integrationId"]; integrationID != "" {
		if err := models.IntegrationID(integrationID).Validate(nil); err != nil {
			return nil, errors.New("invalid integrationId: " + err.Error())
		}
	}

	if integrationType := request.QueryStringParameters["integrationType"]; integrationType != "" {
		if err := models.IntegrationType(integrationType).Validate(nil); err != nil {
			return nil, errors.New("invalid integrationType: " + err.Error())
		}
		result.IntegrationType = aws.String(integrationType)
	}

	if types := request.QueryStringParameters["types"]; types != "" {
		for i, rawType := range strings.Split(types, ",") {
			resourceType, err := url.QueryUnescape(rawType)
			if err != nil {
				return nil, fmt.Errorf("invalid resourceType[%d] %s: %s", i, rawType, err)
			}
			result.Types = append(result.Types, resourceType)
		}

		result.Types = strings.Split(types, ",")
	}

	// ***** Projection *****
	if fields := request.QueryStringParameters["fields"]; fields != "" {
		for _, field := range strings.Split(fields, ",") {
			if field != "" {
				result.Fields = append(result.Fields, field)
			}
		}
	} else {
		result.Fields = defaultFields
	}

	// ***** Sorting *****
	if sortBy := request.QueryStringParameters["sortBy"]; sortBy != "" {
		if _, ok := validSortFields[sortBy]; !ok {
			return nil, errors.New("invalid sortBy: " + sortBy)
		}
		result.SortBy = aws.String(sortBy)
	}

	if sortDir := request.QueryStringParameters["sortDir"]; sortDir != "" {
		if sortDir != "ascending" && sortDir != "descending" {
			return nil, errors.New("invalid sortDir: must be ascending or descending")
		}
		result.SortDir = aws.String(sortDir)
	}

	// ***** Paging *****
	if pageSize := request.QueryStringParameters["pageSize"]; pageSize != "" {
		size, err := strconv.ParseInt(pageSize, 10, 64)
		if err != nil {
			return nil, errors.New("invalid pageSize: " + err.Error())
		}
		if size < 1 {
			return nil, errors.New("invalid pageSize: must be positive")
		}
		result.PageSize = aws.Int64(size)
	}

	if rawPage := request.QueryStringParameters["page"]; rawPage != "" {
		page, err := strconv.ParseInt(rawPage, 10, 64)
		if err != nil {
			return nil, errors.New("invalid page: " + err.Error())
		}
		if page < 1 {
			return nil, errors.New("invalid pageSize: must be positive")
		}
		result.Page = aws.Int64(page)
	}

	return result, nil
}

func buildListScan(params *operations.ListResourcesParams) (*dynamodb.ScanInput, error) {
	var projection expression.ProjectionBuilder
	for i, field := range params.Fields {
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

	if params.Deleted != nil {
		filter = filter.And(expression.Equal(
			expression.Name("deleted"), expression.Value(*params.Deleted)))
	}

	if params.IDContains != nil {
		filter = filter.And(expression.Contains(expression.Name("lowerId"), *params.IDContains))
	}

	if params.IntegrationID != nil {
		filter = filter.And(expression.Equal(
			expression.Name("integrationId"), expression.Value(*params.IntegrationID)))
	}
	if params.IntegrationType != nil {
		filter = filter.And(expression.Equal(
			expression.Name("integrationType"), expression.Value(*params.IntegrationType)))
	}

	if len(params.Types) > 0 {
		var typeFilter expression.ConditionBuilder
		nameExpression := expression.Name("type")

		// Chain OR filters to match one of the specified resource types
		for i, resourceType := range params.Types {
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

	return &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 &env.ResourcesTable,
	}, nil
}

// Scan the table for resources, applying additional filters before returning the results
func listFilteredResources(scanInput *dynamodb.ScanInput, params *operations.ListResourcesParams) ([]*models.Resource, error) {
	result := make([]*models.Resource, 0)
	includeCompliance := false
	for _, field := range params.Fields {
		if field == "complianceStatus" {
			includeCompliance = true
			break
		}
	}

	err := scanPages(scanInput, func(item *resourceItem) error {
		if !includeCompliance {
			result = append(result, item.Resource(""))
			return nil
		}

		status, err := getComplianceStatus(item.ID)
		if err != nil {
			return err
		}

		// Compliance status isn't stored in this table, so we filter it out here if needed
		if params.ComplianceStatus != nil && *params.ComplianceStatus != string(status.Status) {
			return nil
		}

		// Resource passed all of the filters - add it to the result set
		result = append(result, item.Resource(status.Status))
		return nil
	})

	return result, err
}

func sortResources(resources []*models.Resource, sortBy string, ascending bool) {
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
			if left.ComplianceStatus == models.ComplianceStatusERROR || left.ComplianceStatus == models.ComplianceStatusFAIL {
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
			leftTime := strfmt.DateTime(left.LastModified).String()
			rightTime := strfmt.DateTime(right.LastModified).String()

			if leftTime != rightTime {
				if ascending {
					return leftTime < rightTime
				}
				return leftTime > rightTime
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

func pageResources(resources []*models.Resource, pageSize int, page int) *models.ResourceList {
	if len(resources) == 0 {
		// Empty results - there are no pages
		return &models.ResourceList{
			Paging: &models.Paging{
				ThisPage:   aws.Int64(0),
				TotalItems: aws.Int64(0),
				TotalPages: aws.Int64(0),
			},
			Resources: []*models.Resource{},
		}
	}

	totalPages := len(resources) / pageSize
	if len(resources)%pageSize > 0 {
		totalPages++ // Add one more to page count if there is an incomplete page at the end
	}

	paging := &models.Paging{
		ThisPage:   aws.Int64(int64(page)),
		TotalItems: aws.Int64(int64(len(resources))),
		TotalPages: aws.Int64(int64(totalPages)),
	}

	// Truncate policies to just the requested page
	lowerBound := intMin((page-1)*pageSize, len(resources))
	upperBound := intMin(page*pageSize, len(resources))
	return &models.ResourceList{Paging: paging, Resources: resources[lowerBound:upperBound]}
}
