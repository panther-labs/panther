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
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go/service/dynamodb/expression"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
)

const (
	defaultSortDir  = "ascending"
	defaultPage     = 1
	defaultPageSize = 25
)

var (
	statusSortPriority = map[compliancemodels.ComplianceStatus]int{
		compliancemodels.StatusPass:  1,
		compliancemodels.StatusFail:  2,
		compliancemodels.StatusError: 3,
	}
	severitySortPriority = map[compliancemodels.Severity]int{
		compliancemodels.SeverityInfo:     1,
		compliancemodels.SeverityLow:      2,
		compliancemodels.SeverityMedium:   3,
		compliancemodels.SeverityHigh:     4,
		compliancemodels.SeverityCritical: 5,
	}
)

// Here's how the list operations are currently implemented:
//     1. Scan *all* table entries, filtering as much as possible in Dynamo itself
//     2. Perform post-filtering when applicable (compliance status)
//     3. Sort all results
//     4. Truncate results to the requested page number
//
// This is badly inefficient:
//     - Every list operation must scan every table entry
//     - Policy list operations are doubly inefficient because compliance status is managed in a
//       separate compliance-api and requires its own full table scan.
//
// In the worst case, if a caller asks for a page with just 3 policies, 2 full table scans are
// triggered (analysis and compliance tables). Compliance information is cached for a few seconds,
// but otherwise this entire process has to be repeated for every list request.
//
// This inefficiency should make you cringe, but in practice it hasn't mattered much.
// There will never be more than a few hundred entries in the table, so a full scan on every list
// is not that big a deal.
//
// TODO - cursor-based pagination instead of explicit page numbers (web team request)
// This is easy to implement when sorting by ID, because Dynamo's own paging keys can be used to pick
// up future pages where previous calls left off. But this will be harder when sorting by other columns
// like lastModified.

type pythonFilters struct {
	CreatedBy      string
	Enabled        *bool
	IDs            []string
	InitialSet     *bool
	LastModifiedBy string
	NameContains   string
	Severity       []compliancemodels.Severity
	ResourceTypes  []string
	Tags           []string
}

// Dynamo filters common to both ListPolicies and ListRules
func pythonListFilters(input *pythonFilters) []expression.ConditionBuilder {
	var filters []expression.ConditionBuilder

	if input.Enabled != nil {
		filters = append(filters, expression.Equal(
			expression.Name("enabled"), expression.Value(*input.Enabled)))
	}

	if input.NameContains != "" {
		filters = append(filters, expression.Contains(expression.Name("lowerId"), input.NameContains).
			Or(expression.Contains(expression.Name("lowerDisplayName"), input.NameContains)))
	}

	if len(input.IDs) > 0 {
		idFilter := expression.Contains(expression.Name("lowerId"), strings.ToLower(input.IDs[0]))
		for _, id := range input.IDs[1:] {
			idFilter = idFilter.Or(expression.Contains(expression.Name("lowerId"), strings.ToLower(id)))
		}
		filters = append(filters, idFilter)
	}

	if len(input.ResourceTypes) > 0 {
		// a policy with no resource types applies to all of them
		typeFilter := expression.AttributeNotExists(expression.Name("resourceTypes"))
		for _, typeName := range input.ResourceTypes {
			// the item in Dynamo calls this "resourceTypes" for both policies and rules
			typeFilter = typeFilter.Or(expression.Contains(expression.Name("resourceTypes"), typeName))
		}
		filters = append(filters, typeFilter)
	}

	if len(input.Severity) > 0 {
		severityFilter := expression.Equal(expression.Name("severity"), expression.Value(input.Severity[0]))
		for _, severityType := range input.Severity[1:] {
			severityFilter = severityFilter.Or(expression.Equal(expression.Name("severity"),
				expression.Value(severityType)))
		}
		filters = append(filters, severityFilter)
	}

	if len(input.Tags) > 0 {
		tagFilter := expression.Contains(expression.Name("lowerTags"), strings.ToLower(input.Tags[0]))
		for _, tag := range input.Tags[1:] {
			tagFilter = tagFilter.Or(expression.Contains(expression.Name("lowerTags"), strings.ToLower(tag)))
		}
		filters = append(filters, tagFilter)
	}

	if input.InitialSet != nil {
		if *input.InitialSet {
			initialSetFilter := expression.Equal(expression.Name("createdBy"),
				expression.Value(systemUserID))

			filters = append(filters, initialSetFilter)
		} else {
			initialSetFilter := expression.NotEqual(expression.Name("createdBy"),
				expression.Value(systemUserID))

			filters = append(filters, initialSetFilter)
		}
	}

	if input.CreatedBy != "" {
		filters = append(filters, expression.Equal(expression.Name("createdBy"),
			expression.Value(input.CreatedBy)))
	}

	if input.LastModifiedBy != "" {
		filters = append(filters, expression.Equal(expression.Name("lastModifiedBy"),
			expression.Value(input.LastModifiedBy)))
	}

	return filters
}

func sortItems(items []tableItem, sortBy, sortDir string, compliance map[string]complianceStatus) {
	if len(items) <= 1 {
		return
	}

	// ascending by default
	ascending := sortDir != "descending"

	switch sortBy {
	case "displayName":
		sortByDisplayName(items, ascending)
	case "complianceStatus":
		sortByStatus(items, ascending, compliance)
	case "id":
		sortByID(items, ascending)
	case "enabled":
		sortByEnabled(items, ascending)
	case "lastModified":
		sortByLastModified(items, ascending)
	case "logTypes", "resourceTypes", "types":
		sortByType(items, ascending)
	case "severity":
		sortBySeverity(items, ascending)
	default:
		// Input validation for the caller already happens in the struct validate tags.
		// If we reach this code, it means there is a sortBy allowed in the input validation,
		// but not supported in the backend, which should never happen
		panic("Unexpected sortBy: " + sortBy)
	}
}

func sortByDisplayName(items []tableItem, ascending bool) {
	sort.Slice(items, func(i, j int) bool {
		left, right := items[i], items[j]

		var leftName, rightName string
		leftName, rightName = left.LowerDisplayName, right.LowerDisplayName

		// The frontend shows display name *or* ID (when there is no display name)
		// So we sort the same way it is shown to the user - displayName if available, otherwise ID
		if leftName == "" {
			leftName = left.LowerID
		}
		if rightName == "" {
			rightName = right.LowerID
		}

		if leftName != rightName {
			if ascending {
				return leftName < rightName
			}
			return leftName > rightName
		}

		// Same display name: sort by ID
		if ascending {
			return left.LowerID < right.LowerID
		}
		return left.LowerID > right.LowerID
	})
}

func sortByStatus(items []tableItem, ascending bool, compliance map[string]complianceStatus) {
	sort.Slice(items, func(i, j int) bool {
		left, right := items[i], items[j]

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

		leftStatus, rightStatus := compliance[left.ID], compliance[right.ID]

		// Group by compliance status (pass/fail/error)
		if leftStatus != rightStatus {
			if ascending {
				return statusSortPriority[leftStatus.Status] < statusSortPriority[rightStatus.Status]
			}
			return statusSortPriority[leftStatus.Status] > statusSortPriority[rightStatus.Status]
		}

		// Same pass/fail and enabled status: use sort index for ERROR and FAIL
		// This will sort by "top failing": the most failures in order of severity
		if leftStatus.Status == compliancemodels.StatusError || leftStatus.Status == compliancemodels.StatusFail {
			leftIndex := compliance[left.ID].SortIndex
			rightIndex := compliance[right.ID].SortIndex
			if ascending {
				return leftIndex > rightIndex
			}
			return leftIndex < rightIndex
		}

		// Default: sort by ID
		return left.ID < right.ID
	})
}

func sortByEnabled(items []tableItem, ascending bool) {
	sort.Slice(items, func(i, j int) bool {
		left, right := items[i], items[j]
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

func sortByLastModified(items []tableItem, ascending bool) {
	sort.Slice(items, func(i, j int) bool {
		left, right := items[i], items[j]
		if left.LastModified != right.LastModified {
			if ascending {
				return left.LastModified.Before(right.LastModified)
			}
			return left.LastModified.After(right.LastModified)
		}

		// Same timestamp: sort by ID ascending
		return left.ID < right.ID
	})
}

func sortByType(items []tableItem, ascending bool) {
	sort.Slice(items, func(i, j int) bool {
		left, right := items[i], items[j]

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

func sortBySeverity(items []tableItem, ascending bool) {
	sort.Slice(items, func(i, j int) bool {
		left, right := items[i], items[j]
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

func sortByID(items []tableItem, ascending bool) {
	sort.Slice(items, func(i, j int) bool {
		left, right := items[i], items[j]
		if ascending {
			return left.ID < right.ID
		}
		return left.ID > right.ID
	})
}

// Truncate list of items to the requested page
func pageItems(items []tableItem, page, pageSize int) (models.Paging, []tableItem) {
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
