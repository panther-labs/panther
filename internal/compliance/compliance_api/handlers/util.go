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
	"path"
	"sort"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
)

// Severity priority when sorting failed policies
var severityPriority = map[models.Severity]int{
	models.SeverityInfo:     0,
	models.SeverityLow:      1,
	models.SeverityMedium:   2,
	models.SeverityHigh:     3,
	models.SeverityCritical: 4,
}

// Update status counters based on the string status
func updateStatusCount(count *models.StatusCount, status models.ComplianceStatus) {
	switch status {
	case models.StatusPass:
		count.Pass++
	case models.StatusFail:
		count.Fail++
	case models.StatusError:
		count.Error++
	default:
		panic("unknown compliance status " + status)
	}
}

// Convert pass/fail counts to a compliance status string
func countToStatus(count models.StatusCount) models.ComplianceStatus {
	if count.Error > 0 {
		return models.StatusError
	}
	if count.Fail > 0 {
		return models.StatusFail
	}
	return models.StatusPass
}

// Update StatsCountBySeverity totals with a pass/fail status of a given severity
func updateStatusCountBySeverity(
	count *models.StatusCountBySeverity, severity models.Severity, status models.ComplianceStatus) {

	switch severity {
	case models.SeverityInfo:
		updateStatusCount(&count.Info, status)
	case models.SeverityLow:
		updateStatusCount(&count.Low, status)
	case models.SeverityMedium:
		updateStatusCount(&count.Medium, status)
	case models.SeverityHigh:
		updateStatusCount(&count.High, status)
	case models.SeverityCritical:
		updateStatusCount(&count.Critical, status)
	default:
		panic("unknown policy severity " + severity)
	}
}

// Convert pass/fail counts by severity to a compliance status string
func countBySeverityToStatus(count *models.StatusCountBySeverity) models.ComplianceStatus {
	if count.Low.Error > 0 || count.Info.Error > 0 || count.Medium.Error > 0 ||
		count.High.Error > 0 || count.Critical.Error > 0 {

		return models.StatusError
	}

	if count.Low.Fail > 0 || count.Info.Fail > 0 || count.Medium.Fail > 0 ||
		count.High.Fail > 0 || count.Critical.Fail > 0 {

		return models.StatusFail
	}

	return models.StatusPass
}

func sortPoliciesByTopFailing(policies []models.PolicySummary) {
	sort.Slice(policies, func(i, j int) bool {
		left, right := policies[i], policies[j]
		leftFailures := left.Count.Error + left.Count.Fail
		rightFailures := right.Count.Error + right.Count.Fail

		if leftFailures == 0 && rightFailures == 0 {
			// Both passing: sort by ID ascending
			return left.ID < right.ID
		}

		if leftFailures == 0 && rightFailures > 0 {
			// Right failing: it should show first
			return false
		}

		if leftFailures > 0 && rightFailures == 0 {
			// Left failing: it should show first
			return true
		}

		// Both failing: sort highest severity first
		if left.Severity != right.Severity {
			return severityPriority[left.Severity] > severityPriority[right.Severity]
		}

		// Both failing with the same severity: sort total failures+errors descending
		if leftFailures != rightFailures {
			return leftFailures > rightFailures
		}

		// Tiebreaker: sort by ID ascending
		return left.ID < right.ID
	})
}

func sortResourcesByTopFailing(resources []models.ResourceSummary) {
	sort.Slice(resources, func(i, j int) bool {
		left, right := resources[i], resources[j]

		leftFailures := left.Count.Critical.Error + left.Count.Critical.Fail
		rightFailures := right.Count.Critical.Error + right.Count.Critical.Fail
		if leftFailures != rightFailures {
			// Sort highest number of CRITICAL failures first
			return leftFailures > rightFailures
		}

		leftFailures = left.Count.High.Error + left.Count.High.Fail
		rightFailures = right.Count.High.Error + right.Count.High.Fail
		if leftFailures != rightFailures {
			// Sort highest number of HIGH failures next
			return leftFailures > rightFailures
		}

		leftFailures = left.Count.Medium.Error + left.Count.Medium.Fail
		rightFailures = right.Count.Medium.Error + right.Count.Medium.Fail
		if leftFailures != rightFailures {
			// Sort highest number of MEDIUM failures next
			return leftFailures > rightFailures
		}

		leftFailures = left.Count.Low.Error + left.Count.Low.Fail
		rightFailures = right.Count.Low.Error + right.Count.Low.Fail
		if leftFailures != rightFailures {
			// Sort highest number of LOW failures next
			return leftFailures > rightFailures
		}

		leftFailures = left.Count.Info.Error + left.Count.Info.Fail
		rightFailures = right.Count.Info.Error + right.Count.Info.Fail
		if leftFailures != rightFailures {
			// Sort highest number of INFO failures next
			return leftFailures > rightFailures
		}

		// Tiebreaker: sort by ID ascending
		return left.ID < right.ID
	})
}

// Returns true if the resourceID matches an element of the ignore set
func isIgnored(resourceID string, ignoreSet []string) (bool, error) {
	for _, pattern := range ignoreSet {
		match, err := path.Match(pattern, resourceID)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}

	return false, nil
}
