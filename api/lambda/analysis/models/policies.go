package models

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
	"github.com/panther-labs/panther/api/lambda/compliance/models"
)

type CreatePolicyInput = UpdatePolicyInput

type GetPolicyInput struct {
	PolicyID  string `json:"policyId" validate:"required"`
	VersionID string `json:"versionId"`
}

type ListPoliciesInput struct {
	// ----- Filtering -----
	// Only include policies with a specific compliance status
	ComplianceStatus models.ComplianceStatus `json:"complianceStatus"`

	// Only include policies whose ID or display name contains this case-insensitive substring
	NameContains string `json:"nameContains"`

	// Only include policies which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include policies with or without auto-remediation enabled
	HasRemediation *bool `json:"hasRemediation"`

	// Only include policies which apply to one of these resource types
	ResourceTypes []string `json:"resourceTypes" validate:"omitempty,dive,required"`

	// Only include policies with this severity
	Severity models.Severity `json:"severity"`

	// Only include policies with all of these tags (case-insensitive)
	Tags []string `json:"tags" validate:"omitempty,dive,required"`

	// ----- Projection -----
	// Policy fields to return in the response (default: all)
	Fields []string `json:"fields" validate:"omitempty,dive,required"`

	// ----- Sorting -----
	SortBy  string `json:"sortBy" validate:"omitempty,oneof=complianceStatus enabled id lastModified resourceTypes severity"`
	SortDir string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`

	// ----- Paging -----
	PageSize int `json:"pageSize" validate:"min=0"`
	Page     int `json:"page" validate:"min=0"`
}

type ListPoliciesOutput struct {
	Paging   Paging   `json:"paging"`
	Policies []Policy `json:"policies"`
}

type Paging struct {
	ThisPage   int `json:"thisPage"`
	TotalPages int `json:"totalPages"`
	TotalItems int `json:"totalItems"`
}

type SuppressInput struct {
	PolicyIDs []string `json:"policyIds" validate:"min=1,dive,required"`

	// List of resource ID regexes that are excepted from the policy.
	// The policy will still be evaluated, but failures will not trigger alerts nor remediations
	ResourcePatterns []string `json:"resourcePatterns" validate:"min=1,dive,required"`
}

type TestPolicyInput struct {
	Body          string     `json:"body" validate:"required"`
	ResourceTypes []string   `json:"resourceTypes" validate:"omitempty,dive,required"`
	Tests         []UnitTest `json:"tests"`
}

type TestPolicyOutput struct {
	// True if all tests passed
	TestSummary bool `json:"testSummary"`

	// List of test names that passed
	TestsPassed []string `json:"testsPassed"`

	// List of test names that failed
	TestsFailed []string `json:"testsFailed"`

	// List of test names that raised an error, along with their error message
	TestsErrored []TestError `json:"testsErrored"`
}

type TestError struct {
	Name         string `json:"name"`
	ErrorMessage string `json:"errorMessage"`
}

type UpdatePolicyInput struct {
	CoreEntryUpdate
	PythonDetection

	AutoRemediationID         string            `json:"autoRemediationId"`
	AutoRemediationParameters map[string]string `json:"autoRemediationParameters"`
	ResourceTypes             []string          `json:"resourceTypes"`
	Suppressions              []string          `json:"suppressions" validate:"omitempty,dive,required"`
}

type Policy struct {
	CoreEntry
	PythonDetection

	AutoRemediationID         string                  `json:"autoRemediationId"`
	AutoRemediationParameters map[string]string       `json:"autoRemediationParameters"`
	ComplianceStatus          models.ComplianceStatus `json:"complianceStatus"`
	ResourceTypes             []string                `json:"resourceTypes"`
	Suppressions              []string                `json:"suppressions"`
}
