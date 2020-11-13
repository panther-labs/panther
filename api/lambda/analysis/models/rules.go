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

type CreateRuleInput = UpdateRuleInput

type GetRuleInput struct {
	RuleID    string `json:"ruleId" validate:"required"`
	VersionID string `json:"versionId"`
}

type ListRulesInput struct {
	// ----- Filtering -----
	// Only include rules whose ID or display name contains this case-insensitive substring
	NameContains string `json:"nameContains"`

	// Only include rules which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include rules which apply to one of these log types
	LogTypes []string `json:"logTypes" validate:"omitempty,dive,required"`

	// Only include policies with this severity
	Severity models.Severity `json:"severity"`

	// Only include policies with all of these tags (case-insensitive)
	Tags []string `json:"tags" validate:"omitempty,dive,required"`

	// ----- Projection -----
	// Policy fields to return in the response (default: all)
	Fields []string `json:"fields" validate:"omitempty,dive,required"`

	// ----- Sorting -----
	SortBy  string `json:"sortBy" validate:"omitempty,oneof=enabled id lastModified logTypes severity"`
	SortDir string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`

	// ----- Paging -----
	PageSize int `json:"pageSize" validate:"min=0"`
	Page     int `json:"page" validate:"min=0"`
}

type ListRulesOutput struct {
	Paging Paging `json:"paging"`
	Rules  []Rule `json:"rules"`
}

type TestRuleInput struct {
	Body     string     `json:"body" validate:"required"`
	LogTypes []string   `json:"logTypes" validate:"omitempty,dive,required"`
	Tests    []UnitTest `json:"tests"`
}

type TestRuleOutput struct {
	TestSummary bool             `json:"testSummary"`
	Results     []RuleTestResult `json:"results"`
}

type RuleTestResult struct {
	Errored    bool `json:"errored"`
	Passed     bool `json:"passed"`
	RuleOutput bool `json:"ruleOutput"`

	AlertContextError  string `json:"alertContextError"`
	AlertContextOutput string `json:"alertContextOutput"`
	ID                 string `json:"id"`
	RuleID             string `json:"ruleId"`
	RuleError          string `json:"ruleError"`
	TestName           string `json:"testName"`
	TitleError         string `json:"titleError"`
	TitleOutput        string `json:"titleOutput"`
	DedupError         string `json:"dedupError"`
	DedupOutput        string `json:"dedupOutput"`

	// An error produced before running any of the rule functions, like import or syntax error.
	GenericError string `json:"genericError"`
}

type UpdateRuleInput struct {
	CoreEntryUpdate
	PythonDetection

	DedupPeriodMinutes int      `json:"dedupPeriodMinutes" validate:"min=0"`
	LogTypes           []string `json:"logTypes" validate:"omitempty,dive,required"`
	Threshold          int      `json:"threshold" validate:"min=0"`
}

type Rule struct {
	CoreEntry
	PythonDetection

	DedupPeriodMinutes int      `json:"dedupPeriodMinutes"`
	LogTypes           []string `json:"logTypes"`
	Threshold          int      `json:"threshold"`
}
