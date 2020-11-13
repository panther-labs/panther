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

	"github.com/panther-labs/panther/api/gateway/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

const (
	defaultSortBy        = "severity"
	defaultSortAscending = false
	defaultPage          = 1
	defaultPageSize      = 25
)

var (
	statusSortPriority = map[models.ComplianceStatus]int{
		models.ComplianceStatusPASS:  1,
		models.ComplianceStatusFAIL:  2,
		models.ComplianceStatusERROR: 3,
	}
	severitySortPriority = map[models.Severity]int{
		models.SeverityINFO:     1,
		models.SeverityLOW:      2,
		models.SeverityMEDIUM:   3,
		models.SeverityHIGH:     4,
		models.SeverityCRITICAL: 5,
	}
)

type listParams struct {
	// filtering
	complianceStatus models.ComplianceStatus
	nameContains     string
	enabled          *bool
	hasRemediation   *bool
	resourceTypes    map[string]bool
	severity         models.Severity
	tags             []string

	// sorting
	sortBy        string
	sortAscending bool

	// paging
	pageSize int
	page     int
}

// ListPolicies pages through policies from a single organization.
func ListPolicies(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	return handleList(request, typePolicy)
}

// ListRules pages through rules from a single organization.
func ListRules(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	return handleList(request, typeRule)
}

// ListDataModels pages through datamodels from a single organization.
func ListDataModels(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	return handleList(request, typeDataModel)
}

func handleList(request *events.APIGatewayProxyRequest, codeType string) *events.APIGatewayProxyResponse {
	params, err := parseList(request, codeType)
	if err != nil {
		return badRequest(err)
	}

	scanInput, err := buildListScan(params, codeType)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// Rules and Policies share filter, sort, and paging logic: PolicySummary is a superset of RuleSummary
	policies, err := listFiltered(scanInput, params)
	if err != nil {
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}
	if len(policies) == 0 {
		paging := &models.Paging{
			ThisPage:   aws.Int64(0),
			TotalItems: aws.Int64(0),
			TotalPages: aws.Int64(0),
		}
		if codeType == typePolicy {
			return gatewayapi.MarshalResponse(
				&models.PolicyList{Paging: paging, Policies: []*models.PolicySummary{}}, http.StatusOK)
		} else if codeType == typeDataModel {
			return gatewayapi.MarshalResponse(
				&models.DataModelList{Paging: paging, DataModels: []*models.DataModelSummary{}}, http.StatusOK)
		}
		return gatewayapi.MarshalResponse(
			&models.RuleList{Paging: paging, Rules: []*models.RuleSummary{}}, http.StatusOK)
	}

	// TODO - filtered policies could be cached to avoid having to query dynamo for subsequent pages
	sortPolicies(policies, params.sortBy, params.sortAscending)
	result := pagePolicies(policies, params.pageSize, params.page)
	if codeType == typePolicy {
		return gatewayapi.MarshalResponse(result, http.StatusOK)
	} else if codeType == typeDataModel {
		// convert to DataModelList
		dataModelResult := &models.DataModelList{
			Paging:     result.Paging,
			DataModels: make([]*models.DataModelSummary, len(result.Policies)),
		}
		for i, policy := range result.Policies {
			dataModelResult.DataModels[i] = &models.DataModelSummary{
				Enabled:      policy.Enabled,
				ID:           policy.ID,
				LastModified: policy.LastModified,
				LogTypes:     policy.ResourceTypes,
			}
		}
		return gatewayapi.MarshalResponse(dataModelResult, http.StatusOK)
	}

	// Downgrade result to RuleSummary (excludes compliance status, remediations, suppressions)
	ruleResult := &models.RuleList{
		Paging: result.Paging,
		Rules:  make([]*models.RuleSummary, len(result.Policies)),
	}
	for i, policy := range result.Policies {
		ruleResult.Rules[i] = &models.RuleSummary{
			DisplayName:  policy.DisplayName,
			Enabled:      policy.Enabled,
			ID:           policy.ID,
			LastModified: policy.LastModified,
			LogTypes:     policy.ResourceTypes,
			OutputIds:    policy.OutputIds,
			Severity:     policy.Severity,
			Tags:         policy.Tags,
			Threshold:    policy.Threshold,
		}
	}
	return gatewayapi.MarshalResponse(ruleResult, http.StatusOK)
}

func parseList(request *events.APIGatewayProxyRequest, codeType string) (*listParams, error) {
	result := listParams{
		complianceStatus: models.ComplianceStatus(request.QueryStringParameters["complianceStatus"]),
		resourceTypes:    make(map[string]bool),
		severity:         models.Severity(request.QueryStringParameters["severity"]),
		sortBy:           defaultSortBy,
		sortAscending:    defaultSortAscending,
		pageSize:         defaultPageSize,
		page:             defaultPage,
	}

	var err error

	if result.complianceStatus != "" {
		if err = result.complianceStatus.Validate(nil); err != nil {
			return nil, errors.New("invalid complianceStatus: " + err.Error())
		}
	}

	result.nameContains, err = url.QueryUnescape(request.QueryStringParameters["nameContains"])
	if err != nil {
		return nil, errors.New("invalid nameContains: " + err.Error())
	}
	result.nameContains = strings.ToLower(result.nameContains)

	if raw := request.QueryStringParameters["enabled"]; raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, errors.New("invalid enabled: " + err.Error())
		}
		result.enabled = aws.Bool(enabled)
	}

	if raw := request.QueryStringParameters["hasRemediation"]; raw != "" {
		hasRemediation, err := strconv.ParseBool(raw)
		if err != nil {
			return nil, errors.New("invalid hasRemediation: " + err.Error())
		}
		result.hasRemediation = aws.Bool(hasRemediation)
	}

	typeKey := "resourceTypes"
	if codeType == typeRule || codeType == typeDataModel {
		typeKey = "logTypes"
	}
	rawTypes := strings.Split(request.QueryStringParameters[typeKey], ",")
	for i, rawType := range rawTypes {
		if rawType == "" {
			continue
		}
		resourceType, err := url.QueryUnescape(rawType)
		if err != nil {
			return nil, fmt.Errorf("invalid %s[%d]: %s", typeKey, i, err)
		}
		result.resourceTypes[resourceType] = true
	}

	if result.severity != "" {
		if err = result.severity.Validate(nil); err != nil {
			return nil, errors.New("invalid severity: " + err.Error())
		}
	}

	rawTags := strings.Split(request.QueryStringParameters["tags"], ",")
	for _, rawTag := range rawTags {
		if rawTag == "" {
			continue
		}
		tag, err := url.QueryUnescape(rawTag)
		if err != nil {
			return nil, errors.New("invalid tag: " + err.Error())
		}
		result.tags = append(result.tags, strings.ToLower(tag))
	}

	if err := parseSortingPaging(request, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func parseSortingPaging(request *events.APIGatewayProxyRequest, result *listParams) error {
	if sortBy := request.QueryStringParameters["sortBy"]; sortBy != "" {
		result.sortBy = sortBy
	}

	if sortDir := request.QueryStringParameters["sortDir"]; sortDir != "" {
		switch sortDir {
		case "ascending":
			result.sortAscending = true
		case "descending":
			result.sortAscending = false
		default:
			return errors.New("invalid sortDir: " + sortDir)
		}
	}

	var err error
	if raw := request.QueryStringParameters["pageSize"]; raw != "" {
		result.pageSize, err = strconv.Atoi(raw)
		if err != nil {
			return errors.New("invalid pageSize: " + err.Error())
		}
		if result.pageSize < 1 {
			return errors.New("invalid pageSize: must be positive")
		}
	}

	if raw := request.QueryStringParameters["page"]; raw != "" {
		result.page, err = strconv.Atoi(raw)
		if err != nil {
			return errors.New("invalid page: " + err.Error())
		}
		if result.page < 1 {
			return errors.New("invalid page: must be positive")
		}
	}

	return nil
}

func buildListScan(params *listParams, codeType string) (*dynamodb.ScanInput, error) {
	projection := expression.NamesList(
		// only fields needed for frontend rule/policy list
		expression.Name("autoRemediationId"),
		expression.Name("autoRemediationParameters"),
		expression.Name("displayName"),
		expression.Name("enabled"),
		expression.Name("id"),
		expression.Name("lastModified"),
		expression.Name("resourceTypes"),
		expression.Name("severity"),
		expression.Name("suppressions"),
		expression.Name("tags"),
		expression.Name("type"),
		expression.Name("threshold"),
		expression.Name("outputIds"),
	)

	filter := expression.Equal(expression.Name("type"), expression.Value(codeType))
	if params.nameContains != "" {
		filter = filter.And(
			expression.Contains(expression.Name("lowerId"), params.nameContains).
				Or(expression.Contains(expression.Name("lowerDisplayName"), params.nameContains)))
	}

	if params.enabled != nil {
		filter = filter.And(expression.Equal(
			expression.Name("enabled"), expression.Value(*params.enabled)))
	}

	if params.hasRemediation != nil {
		if *params.hasRemediation {
			// We only want policies with a remediation specified
			filter = filter.And(expression.AttributeExists(expression.Name("autoRemediationId")))
		} else {
			// We only want policies without a remediation id
			filter = filter.And(expression.AttributeNotExists(expression.Name("autoRemediationId")))
		}
	}

	if len(params.resourceTypes) > 0 {
		// a policy with no resource types applies to all of them
		typeFilter := expression.AttributeNotExists(expression.Name("resourceTypes"))
		for typeName := range params.resourceTypes {
			typeFilter = typeFilter.Or(expression.Contains(expression.Name("resourceTypes"), typeName))
		}
		filter = filter.And(typeFilter)
	}

	// severity doesn't apply to data models
	if params.severity != "" && codeType != typeDataModel {
		filter = filter.And(expression.Equal(
			expression.Name("severity"), expression.Value(params.severity)))
	}

	if len(params.tags) > 0 {
		tagFilter := expression.AttributeExists(expression.Name("lowerTags"))
		for _, tag := range params.tags {
			tagFilter = tagFilter.And(expression.Contains(expression.Name("lowerTags"), tag))
		}
		filter = filter.And(tagFilter)
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
		TableName:                 &env.Table,
	}, nil
}

// Query the table, applying additional filters before returning the results
func listFiltered(scanInput *dynamodb.ScanInput, params *listParams) ([]*models.PolicySummary, error) {
	var result []*models.PolicySummary
	err := scanPages(scanInput, func(item *tableItem) error {
		if item.Type != typePolicy {
			// Log analysis rules and data models do not have a compliance status
			result = append(result, item.PolicySummary(""))
			return nil
		}

		status, err := getComplianceStatus(item.ID)
		if err != nil {
			return err
		}

		// Compliance status isn't stored in the policy table, so we filter it out here
		if params.complianceStatus != "" && status.Status != params.complianceStatus {
			return nil
		}

		// Policy passed all of the filters - add it to the result set
		result = append(result, item.PolicySummary(status.Status))
		return nil
	})

	return result, err
}

func sortPolicies(policies []*models.PolicySummary, sortBy string, ascending bool) {
	if len(policies) <= 1 {
		return
	}

	switch sortBy {
	case "complianceStatus":
		sortByStatus(policies, ascending, complianceCache.Policies)
	case "enabled":
		sortByEnabled(policies, ascending)
	case "lastModified":
		sortByLastModified(policies, ascending)
	case "logTypes", "resourceTypes":
		sortByType(policies, ascending)
	case "severity":
		sortBySeverity(policies, ascending)
	default:
		sortByID(policies, ascending)
	}
}

func sortByStatus(policies []*models.PolicySummary, ascending bool, policyStatus map[models.ID]*complianceStatus) {
	sort.Slice(policies, func(i, j int) bool {
		left, right := policies[i], policies[j]

		// Group all disabled policies together at the end.
		// Technically, disabled policies still have a pass/fail status,
		// we just don't show it yet in the web app.
		// The "disabled" status overrides the "pass/fail" status
		// TODO - remove this block once enabled/disabled status is shown separately (ETA v1.9)
		//
		// So the sort order is essentially:
		//     PASS < FAIL < ERROR < PASS/DISABLED < FAIL/DISABLED < ERROR/DISABLED
		// Which will appear to the user as:
		//     PASS < FAIL < ERROR < DISABLED
		if left.Enabled != right.Enabled {
			// Same logic as sortByEnabled()
			if left.Enabled && !right.Enabled {
				return ascending
			}
			return !ascending
		}

		// Group by compliance status (pass/fail/error)
		if left.ComplianceStatus != right.ComplianceStatus {
			if ascending {
				return statusSortPriority[left.ComplianceStatus] < statusSortPriority[right.ComplianceStatus]
			}
			return statusSortPriority[left.ComplianceStatus] > statusSortPriority[right.ComplianceStatus]
		}

		// Same pass/fail and enabled status: use sort index for ERROR and FAIL
		// This will sort by "top failing": the most failures in order of severity
		if left.ComplianceStatus == models.ComplianceStatusERROR || left.ComplianceStatus == models.ComplianceStatusFAIL {
			// The status cache has already been populated, we can access it directly
			leftIndex := policyStatus[left.ID].SortIndex
			rightIndex := policyStatus[right.ID].SortIndex
			if ascending {
				return leftIndex > rightIndex
			}
			return leftIndex < rightIndex
		}

		// Default: sort by ID
		return left.ID < right.ID
	})
}

func sortByEnabled(policies []*models.PolicySummary, ascending bool) {
	sort.Slice(policies, func(i, j int) bool {
		left, right := policies[i], policies[j]
		if left.Enabled && !right.Enabled {
			// when ascending (default): enabled < disabled
			return ascending
		}

		if !left.Enabled && right.Enabled {
			// when ascending: disabled > enabled
			return !ascending
		}

		// Same enabled status: sort by ID ascending
		return left.ID < right.ID
	})
}

func sortByLastModified(policies []*models.PolicySummary, ascending bool) {
	sort.Slice(policies, func(i, j int) bool {
		left, right := policies[i], policies[j]
		leftTime := strfmt.DateTime(left.LastModified).String()
		rightTime := strfmt.DateTime(right.LastModified).String()

		if leftTime != rightTime {
			if ascending {
				return leftTime < rightTime
			}
			return leftTime > rightTime
		}

		// Same timestamp: sort by ID ascending
		return left.ID < right.ID
	})
}

func sortByType(policies []*models.PolicySummary, ascending bool) {
	sort.Slice(policies, func(i, j int) bool {
		left, right := policies[i], policies[j]

		// The resource types are already sorted:
		// compare them pairwise, sorting by the first differing element.
		for t := 0; t < intMin(len(left.ResourceTypes), len(right.ResourceTypes)); t++ {
			leftType, rightType := left.ResourceTypes[t], right.ResourceTypes[t]
			if leftType != rightType {
				if ascending {
					return leftType < rightType
				}
				return leftType > rightType
			}
		}

		// Same resource types: sort by ID ascending
		return left.ID < right.ID
	})
}

func sortBySeverity(policies []*models.PolicySummary, ascending bool) {
	sort.Slice(policies, func(i, j int) bool {
		left, right := policies[i], policies[j]
		leftSort, rightSort := severitySortPriority[left.Severity], severitySortPriority[right.Severity]

		if leftSort != rightSort {
			if ascending {
				return leftSort < rightSort
			}
			return leftSort > rightSort
		}

		// Same severity: sort by ID ascending
		return left.ID < right.ID
	})
}

func sortByID(policies []*models.PolicySummary, ascending bool) {
	sort.Slice(policies, func(i, j int) bool {
		left, right := policies[i], policies[j]
		if ascending {
			return left.ID < right.ID
		}
		return left.ID > right.ID
	})
}

func pagePolicies(policies []*models.PolicySummary, pageSize int, page int) *models.PolicyList {
	totalPages := len(policies) / pageSize
	if len(policies)%pageSize > 0 {
		totalPages++ // Add one more to page count if there is an incomplete page at the end
	}

	paging := &models.Paging{
		ThisPage:   aws.Int64(int64(page)),
		TotalItems: aws.Int64(int64(len(policies))),
		TotalPages: aws.Int64(int64(totalPages)),
	}

	// Truncate policies to just the requested page
	lowerBound := intMin((page-1)*pageSize, len(policies))
	upperBound := intMin(page*pageSize, len(policies))
	return &models.PolicyList{Paging: paging, Policies: policies[lowerBound:upperBound]}
}
