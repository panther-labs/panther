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

type CreateRuleInput = UpdateRuleInput

type DeleteRulesInput = DeletePoliciesInput

type GetRuleInput struct {
	ID        string `json:"id" validate:"required,max=1000"`
	VersionID string `json:"versionId" validate:"omitempty,len=32"`
}

type ListRulesInput struct {
	// ----- Filtering -----
	// Only include rules whose ID or display name contains this case-insensitive substring
	NameContains string `json:"nameContains" validate:"max=1000"`

	// Only include rules which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include rules which apply to one of these log types
	LogTypes []string `json:"logTypes" validate:"max=500,dive,required,max=500"`

	// Only include policies with this severity
	Severity []models.Severity `json:"severity" validate:"dive,oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// Only include policies with all of these tags (case-insensitive)
	Tags []string `json:"tags" validate:"max=500,dive,required,max=500"`

	// ----- Projection -----
	// Policy fields to return in the response (default: all)
	Fields []string `json:"fields" validate:"max=20,dive,required,max=100"`

	// ----- Sorting -----
	SortBy  string `json:"sortBy" validate:"omitempty,oneof=displayName enabled id lastModified logTypes severity"`
	SortDir string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`

	// ----- Paging -----
	PageSize int `json:"pageSize" validate:"min=0,max=1000"`
	Page     int `json:"page" validate:"min=0"`

	// Only include rules whose creator matches this user ID (which need not be a uuid)
	CreatedBy string `json:"createdBy"`

	// Only include rules which were last modified by this user ID
	LastModifiedBy string `json:"lastModifiedBy"`

	// If True, include only rules which were created by the system during the initial deployment
	// If False, include only rules where were NOT created by the system during the initial deployment
	InitialSet *bool `json:"initialSet"`
}

type ListRulesOutput struct {
	Paging Paging `json:"paging"`
	Rules  []Rule `json:"rules"`
}

type TestRuleInput struct {
	Body     string     `json:"body" validate:"required,max=100000"`
	LogTypes []string   `json:"logTypes" validate:"max=500,dive,required,max=500"`
	Tests    []UnitTest `json:"tests" validate:"max=500,dive"`
}

type TestRuleOutput struct {
	Results []TestRuleRecord `json:"results"`
}

type TestRuleRecord struct {
	ID        string                  `json:"id"`
	Name      string                  `json:"name"`
	Passed    bool                    `json:"passed"`
	Functions TestRuleRecordFunctions `json:"functions"`

	// An error produced before running any of the rule functions, like import or syntax error.
	Error *TestError `json:"error"`
}

type TestRuleRecordFunctions struct {
	Rule         *TestDetectionSubRecord `json:"ruleFunction"`
	Title        *TestDetectionSubRecord `json:"titleFunction"`
	Dedup        *TestDetectionSubRecord `json:"dedupFunction"`
	AlertContext *TestDetectionSubRecord `json:"alertContextFunction"`
	Description  *TestDetectionSubRecord `json:"descriptionFunction"`
	Destinations *TestDetectionSubRecord `json:"destinationsFunction"`
	Reference    *TestDetectionSubRecord `json:"referenceFunction"`
	Runbook      *TestDetectionSubRecord `json:"runbookFunction"`
	Severity     *TestDetectionSubRecord `json:"severityFunction"`
}

type UpdateRuleInput struct {
	AnalysisType       DetectionType       `json:"analysisType"`
	Body               string              `json:"body" validate:"required,max=100000"`
	DedupPeriodMinutes int                 `json:"dedupPeriodMinutes" validate:"min=0"`
	Description        string              `json:"description" validate:"max=10000"`
	DisplayName        string              `json:"displayName" validate:"max=1000,excludesall='<>&\""`
	Enabled            bool                `json:"enabled"`
	ID                 string              `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	LogTypes           []string            `json:"logTypes" validate:"max=500,dive,required,max=500"`
	OutputIDs          []string            `json:"outputIds" validate:"max=500,dive,required,max=5000"`
	Reference          string              `json:"reference" validate:"max=10000"`
	Reports            map[string][]string `json:"reports" validate:"max=500"`
	Runbook            string              `json:"runbook" validate:"max=10000"`
	Severity           models.Severity     `json:"severity" validate:"oneof=INFO LOW MEDIUM HIGH CRITICAL"`
	Tags               []string            `json:"tags" validate:"max=500,dive,required,max=1000"`
	Tests              []UnitTest          `json:"tests" validate:"max=500,dive"`
	Threshold          int                 `json:"threshold" validate:"min=0"`
	UserID             string              `json:"userId" validate:"required"`
}

type Rule struct {
	AnalysisType       DetectionType       `json:"analysisType"`
	Body               string              `json:"body"`
	CreatedAt          time.Time           `json:"createdAt"`
	CreatedBy          string              `json:"createdBy"`
	DedupPeriodMinutes int                 `json:"dedupPeriodMinutes"`
	Description        string              `json:"description"`
	DisplayName        string              `json:"displayName"`
	Enabled            bool                `json:"enabled"`
	ID                 string              `json:"id"`
	LastModified       time.Time           `json:"lastModified"`
	LastModifiedBy     string              `json:"lastModifiedBy"`
	LogTypes           []string            `json:"logTypes"`
	OutputIDs          []string            `json:"outputIds"`
	Reference          string              `json:"reference"`
	Reports            map[string][]string `json:"reports"`
	Runbook            string              `json:"runbook"`
	Severity           models.Severity     `json:"severity"`
	Tags               []string            `json:"tags"`
	Tests              []UnitTest          `json:"tests"`
	Threshold          int                 `json:"threshold"`
	VersionID          string              `json:"versionId"`
}
