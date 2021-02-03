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
	"time"

	"github.com/panther-labs/panther/api/lambda/compliance/models"
)

type CreatePolicyInput = UpdatePolicyInput

type DeletePoliciesInput struct {
	Entries []DeleteEntry `json:"entries" validate:"min=1,max=1000,dive"`
}

type DeleteEntry struct {
	ID string `json:"id" validate:"required,max=1000"`
}

type GetPolicyInput struct {
	ID        string `json:"id" validate:"required,max=1000"`
	VersionID string `json:"versionId" validate:"omitempty,len=32"`
}

type ListPoliciesInput struct {
	// ----- Filtering -----
	// Only include policies with a specific compliance status
	ComplianceStatus models.ComplianceStatus `json:"complianceStatus" validate:"omitempty,oneof=PASS FAIL ERROR"`

	// Only include policies whose ID or display name contains this case-insensitive substring
	NameContains string `json:"nameContains" validate:"max=1000"`

	// Only include policies which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include policies with or without auto-remediation enabled
	HasRemediation *bool `json:"hasRemediation"`

	// Only include policies which apply to one of these resource types
	ResourceTypes []string `json:"resourceTypes" validate:"max=500,dive,required,max=500"`

	// Only include policies with this severity
	Severity []models.Severity `json:"severity" validate:"dive,oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// Only include policies with all of these tags (case-insensitive)
	Tags []string `json:"tags" validate:"max=500,dive,required,max=500"`

	// ----- Projection -----
	// Policy fields to return in the response (default: all)
	Fields []string `json:"fields" validate:"max=20,dive,required,max=100"`

	// ----- Sorting -----
	SortBy  string `json:"sortBy" validate:"omitempty,oneof=complianceStatus enabled id lastModified resourceTypes severity"`
	SortDir string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`

	// ----- Paging -----
	PageSize int `json:"pageSize" validate:"min=0,max=1000"`
	Page     int `json:"page" validate:"min=0"`

	// Only include policies whose creator matches this user ID (which need not be a uuid)
	CreatedBy string `json:"createdBy"`

	// Only include policies which were last modified by this user ID
	LastModifiedBy string `json:"lastModifiedBy"`

	// If True, include only policies which were created by the system during the initial deployment
	// If False, include only policies where were NOT created by the system during the initial deployment
	InitialSet *bool `json:"initialSet"`
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
	PolicyIDs []string `json:"policyIds" validate:"min=1,dive,required,max=1000"`

	// List of resource ID regexes that are excepted from the policy.
	// The policy will still be evaluated, but failures will not trigger alerts nor remediations
	ResourcePatterns []string `json:"resourcePatterns" validate:"min=1,dive,required,max=10000"`
}

type TestPolicyInput struct {
	Body          string     `json:"body" validate:"required,max=100000"`
	ResourceTypes []string   `json:"resourceTypes" validate:"max=500,dive,required,max=500"`
	Tests         []UnitTest `json:"tests" validate:"max=500,dive"`
}

type TestPolicyOutput struct {
	Results []TestPolicyRecord `json:"results"`
}

type TestPolicyRecord struct {
	ID        string                    `json:"id"`
	Name      string                    `json:"name"`
	Passed    bool                      `json:"passed"`
	Functions TestPolicyRecordFunctions `json:"functions"`
	Error     *TestError                `json:"error"`
}

type TestPolicyRecordFunctions struct {
	Policy TestDetectionSubRecord `json:"policyFunction"`
}

type TestDetectionSubRecord struct {
	Output *string    `json:"output"`
	Error  *TestError `json:"error"`
}

type TestError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type UpdatePolicyInput struct {
	AnalysisType              DetectionType       `json:"analysisType"`
	AutoRemediationID         string              `json:"autoRemediationId" validate:"max=1000"`
	AutoRemediationParameters map[string]string   `json:"autoRemediationParameters" validate:"max=500"`
	Body                      string              `json:"body" validate:"required,max=100000"`
	Description               string              `json:"description" validate:"max=10000"`
	DisplayName               string              `json:"displayName" validate:"max=1000,excludesall='<>&\""`
	Enabled                   bool                `json:"enabled"`
	ID                        string              `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	OutputIDs                 []string            `json:"outputIds" validate:"max=500,dive,required,max=5000"`
	Reference                 string              `json:"reference" validate:"max=10000"`
	Reports                   map[string][]string `json:"reports" validate:"max=500"`
	ResourceTypes             []string            `json:"resourceTypes" validate:"max=500,dive,required,max=500"`
	Runbook                   string              `json:"runbook" validate:"max=10000"`
	Severity                  models.Severity     `json:"severity" validate:"oneof=INFO LOW MEDIUM HIGH CRITICAL"`
	Suppressions              []string            `json:"suppressions" validate:"max=500,dive,required,max=1000"`
	Tags                      []string            `json:"tags" validate:"max=500,dive,required,max=1000"`
	Tests                     []UnitTest          `json:"tests" validate:"max=500,dive"`
	UserID                    string              `json:"userId" validate:"required"`
}

// The validate tags here are used by BulkUpload
type Policy struct {
	AnalysisType              DetectionType           `json:"analysisType"`
	AutoRemediationID         string                  `json:"autoRemediationId" validate:"max=1000"`
	AutoRemediationParameters map[string]string       `json:"autoRemediationParameters" validte:"max=500"`
	Body                      string                  `json:"body" validate:"required,max=100000"`
	ComplianceStatus          models.ComplianceStatus `json:"complianceStatus"`
	CreatedAt                 time.Time               `json:"createdAt"`
	CreatedBy                 string                  `json:"createdBy"`
	Description               string                  `json:"description" validate:"max=10000"`
	DisplayName               string                  `json:"displayName" validate:"max=1000,excludesall='<>&\""`
	Enabled                   bool                    `json:"enabled"`
	ID                        string                  `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	LastModified              time.Time               `json:"lastModified"`
	LastModifiedBy            string                  `json:"lastModifiedBy"`
	OutputIDs                 []string                `json:"outputIds" validate:"max=500,dive,required,max=5000"`
	Reference                 string                  `json:"reference" validate:"max=10000"`
	Reports                   map[string][]string     `json:"reports" validate:"max=500"`
	ResourceTypes             []string                `json:"resourceTypes" validate:"max=500,dive,required,max=500"`
	Runbook                   string                  `json:"runbook" validate:"max=10000"`
	Severity                  models.Severity         `json:"severity" validate:"oneof=INFO LOW MEDIUM HIGH CRITICAL"`
	Suppressions              []string                `json:"suppressions" validate:"max=500,dive,required,max=1000"`
	Tags                      []string                `json:"tags" validate:"max=500,dive,required,max=1000"`
	Tests                     []UnitTest              `json:"tests" validate:"max=500,dive"`
	VersionID                 string                  `json:"versionId"`
}
