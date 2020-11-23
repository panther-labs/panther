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
	"github.com/aws/aws-sdk-go/service/dynamodb"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
)

// Common query logic for both DescribePolicy and DescribeResource.
func policyResourceDetail(
	input *dynamodb.QueryInput,
	page, pageSize int,
	severity models.Severity,
	status models.ComplianceStatus,
	suppressed *bool,
) (*models.PolicyResourceDetail, error) {

	if page == 0 {
		page = models.DefaultPage
	}
	if pageSize == 0 {
		pageSize = models.DefaultPageSize
	}

	// TODO - global totals could be cached so not every page query has to scan everything
	result := models.PolicyResourceDetail{
		Items:  make([]models.ComplianceEntry, 0, pageSize),
		Status: models.StatusPass,
	}

	err := queryPages(input, func(item *models.ComplianceEntry) error {
		addItemToResult(item, &result, page, pageSize, severity, status, suppressed)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Compute the total number of pages needed to show all the matching results
	result.Paging.TotalPages = result.Paging.TotalItems / pageSize
	remainder := result.Paging.TotalItems % pageSize
	if remainder > 0 {
		result.Paging.TotalPages++
	}

	if result.Paging.TotalItems > 0 {
		result.Paging.ThisPage = page
	}

	return &result, nil
}

// Update the paging result with a single compliance status entry.
func addItemToResult(
	item *models.ComplianceEntry,
	result *models.PolicyResourceDetail,
	page, pageSize int,
	severity models.Severity,
	status models.ComplianceStatus,
	suppressed *bool,
) {

	// Update overall status and global totals (pre-filter)
	// ERROR trumps FAIL trumps PASS
	switch item.Status {
	case models.StatusError:
		if item.Suppressed {
			result.Totals.Suppressed.Error++
		} else {
			result.Status = models.StatusError
			result.Totals.Active.Error++
		}

	case models.StatusFail:
		if item.Suppressed {
			result.Totals.Suppressed.Fail++
		} else {
			if result.Status != models.StatusError {
				result.Status = models.StatusFail
			}
			result.Totals.Active.Fail++
		}

	case models.StatusPass:
		if item.Suppressed {
			result.Totals.Suppressed.Pass++
		} else {
			result.Totals.Active.Pass++
		}

	default:
		panic("unknown compliance status " + item.Status)
	}

	// Drop this table entry if it doesn't match the filters
	if !itemMatchesFilter(item, severity, status, suppressed) {
		return
	}

	result.Paging.TotalItems++
	firstItem := (page-1)*pageSize + 1 // first matching item # in the requested page
	if result.Paging.TotalItems >= firstItem && len(result.Items) < pageSize {
		// This matching item is in the requested page number
		result.Items = append(result.Items, *item)
	}
}

func itemMatchesFilter(
	item *models.ComplianceEntry,
	severity models.Severity,
	status models.ComplianceStatus,
	suppressed *bool,
) bool {

	if severity != "" && severity != item.PolicySeverity {
		return false
	}
	if status != "" && status != item.Status {
		return false
	}
	if suppressed != nil && *suppressed != item.Suppressed {
		return false
	}

	return true
}
