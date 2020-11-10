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

type DetectionType string

const (
	TypePolicy DetectionType = "POLICY"
	TypeRule   DetectionType = "RULE"
	TypeGlobal DetectionType = "GLOBAL"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type LambdaInput struct {
	// Globals
	CreateGlobal  *CreateGlobalInput  `json:"createGlobal"`
	DeleteGlobals *DeleteGlobalsInput `json:"deleteGlobals"`
	GetGlobal     *GetGlobalInput     `json:"getGlobal"`

	// Policies (cloud security)
	// TODO - can we combine all the policy/rule endpoints since they're so similar?
	CreatePolicy *CreatePolicyInput `json:"createPolicy"`
	GetPolicy    *GetPolicyInput    `json:"getPolicy"`
	ListPolicies *ListPoliciesInput `json:"listPolicies"`
	Suppress     *SuppressInput     `json:"suppressInput"`

	// Rules (log analysis)
	CreateRule *CreateRuleInput `json:"createRule"`
	GetRule    *GetRuleInput    `json:"getRule"`
	UpdateRule *UpdateRuleInput `json:"updateRule"`

	// Shared
	DeleteDetections *DeleteDetectionsInput `json:"deleteDetections"`
	//GetEnabledDetections *GetEnabledDetectionsInput `json:"getEnabledDetections"`
}

/***** Globals *****/
type CreateGlobalInput = UpdateGlobalInput

type DeleteGlobalsInput = DeleteDetectionsInput

type GetGlobalInput struct {
	GlobalID  string `json:"globalId" validate:"required"`
	VersionID string `json:"versionId"`
}

type UpdateGlobalInput struct {
	// TODO - is the body needed if someone just wants to update the metadata?
	Body        string   `json:"body" validate:"required"`
	Description string   `json:"description"`
	ID          string   `json:"id" validate:"required"`
	Tags        []string `json:"tags" validate:"omitempty,dive,required"`
	UserID      string   `json:"userId" validate:"uuid4"`
}

type Global struct {
	Body           string    `json:"body"`
	CreatedAt      time.Time `json:"createdAt"`
	CreatedBy      string    `json:"createdBy"`
	Description    string    `json:"description"`
	ID             string    `json:"id"`
	LastModified   time.Time `json:"lastModified"`
	LastModifiedBy string    `json:"lastModifiedBy"`
	Tags           []string  `json:"tags"`
	VersionID      string    `json:"versionId"`
}

/***** Policies *****/
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
	Severity Severity `json:"severity"`

	// Only include policies with all of these tags (case-insensitive)
	Tags []string `json:"tags" validate:"omitempty,dive,required"`

	// ----- Projection -----
	// Policy fields to return in the response (default: all)
	// TODO - update appsync to specify the fields needed for frontend here
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
	ResourcePatterns []string `json:"resourcePatterns"`
}

type UpdatePolicyInput struct {
	// Core fields
	Body        string   `json:"body" validate:"required,min=5"`
	Description string   `json:"description"`
	ID          string   `json:"id" validate:"required"`
	Tags        []string `json:"tags" validate:"omitempty,dive,required"`

	AutoRemediationID         string            `json:"autoRemediationId"`
	AutoRemediationParameters map[string]string `json:"autoRemediationParameters"`
	DisplayName               string            `json:"displayName"`
	Enabled                   bool              `json:"enabled"`
	OutputIDs                 []string          `json:"outputIds" validate:"omitempty,dive,required"`
	Reference                 string            `json:"reference"`
	ResourceTypes             []string          `json:"resourceTypes"`
	Runbook                   string            `json:"runbook"`
	Severity                  Severity          `json:"severity"`
	Suppressions              []string          `json:"suppressions" validate:"omitempty,dive,required"`
	Tests                     []UnitTest        `json:"tests" validate:"dive"`
	UserID                    string            `json:"userId" validate:"required,uuid4"`

	// TODO - should reports be part of this?
}

type Policy struct {
	// Core fields (shared with globals)
	Body           string    `json:"body"`
	CreatedAt      time.Time `json:"createdAt"`
	CreatedBy      string    `json:"createdBy"`
	Description    string    `json:"description"`
	ID             string    `json:"id"`
	LastModified   time.Time `json:"lastModified"`
	LastModifiedBy string    `json:"lastModifiedBy"`
	Tags           []string  `json:"tags"`
	VersionID      string    `json:"versionId"`

	// Unique to policies
	// TODO - create shared models for CoreDetection and PythonDetection
	// (which can also be used for the input structs)
	AutoRemediationID         string                  `json:"autoRemediationId"`
	AutoRemediationParameters map[string]string       `json:"autoRemediationParameters"`
	ComplianceStatus          models.ComplianceStatus `json:"complianceStatus"`
	ResourceTypes             []string                `json:"resourceTypes"`
	Suppressions              []string                `json:"suppressions"`

	// shared with rules
	DisplayName string              `json:"displayName"`
	Enabled     bool                `json:"enabled"`
	OutputIDs   []string            `json:"outputIds"`
	Reference   string              `json:"reference"`
	Reports     map[string][]string `json:"reports"`
	Runbook     string              `json:"runbook"`
	Severity    Severity            `json:"severity"`
	Tests       []UnitTest          `json:"tests"`
}

type UnitTest struct {
	ExpectedResult bool   `json:"expectedResult"`
	Name           string `json:"name" validate:"required"`
	Resource       string `json:"resource" validate:"required"`
}

/***** Rules *****/
type CreateRuleInput = UpdateRuleInput

type GetRuleInput struct {
	RuleID    string `json:"ruleId" validate:"required"` 
	VersionID string `json:"versionId"`
}

// TODO: combine with ListPoliciesInput, either using embedding subset of common fields or creating
// a single shared model (union)
type ListRulesInput struct {
	// ----- Filtering -----
	// Only include rules whose ID or display name contains this case-insensitive substring
	NameContains string `json:"nameContains"`

	// Only include rules which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include rules which apply to one of these log types
	LogTypes []string `json:"logTypes" validate:"omitempty,dive,required"`

	// Only include policies with this severity
	Severity Severity `json:"severity"`

	// Only include policies with all of these tags (case-insensitive)
	Tags []string `json:"tags" validate:"omitempty,dive,required"`

	// ----- Projection -----
	// Policy fields to return in the response (default: all)
	// TODO - update appsync to specify the fields needed for frontend here
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

type UpdateRuleInput struct {
	// Core fields
	Body        string   `json:"body" validate:"required,min=5"`
	Description string   `json:"description"`
	ID          string   `json:"id" validate:"required"`
	Tags        []string `json:"tags" validate:"omitempty,dive,required"`
	UserID      string   `json:"userId" validate:"required,uuid4"`

	// Shared with policies
	DisplayName string              `json:"displayName"`
	Enabled     bool                `json:"enabled"`
	OutputIDs   []string            `json:"outputIds" validate:"omitempty,dive,required"`
	Reference   string              `json:"reference"`
	Reports     map[string][]string `json:"reports"`
	Runbook     string              `json:"runbook"`
	Severity    Severity            `json:"severity"`
	Tests       []UnitTest          `json:"tests" validate:"dive"`

	// Unique to rules
	DedupPeriodMinutes int      `json:"dedupPeriodMinutes" validate:"min=0"`
	LogTypes           []string `json:"logTypes" validate:"omitempty,dive,required"`
	Threshold          int      `json:"threshold" validate:"min=0"`
}

type Rule struct {
	// Core fields (shared with globals)
	Body           string    `json:"body"`
	CreatedAt      time.Time `json:"createdAt"`
	CreatedBy      string    `json:"createdBy"`
	Description    string    `json:"description"`
	ID             string    `json:"id"`
	LastModified   time.Time `json:"lastModified"`
	LastModifiedBy string    `json:"lastModifiedBy"`
	Tags           []string  `json:"tags"`
	VersionID      string    `json:"versionId"`

	// shared with policies
	DisplayName string              `json:"displayName"`
	Enabled     bool                `json:"enabled"`
	OutputIDs   []string            `json:"outputIds"`
	Reference   string              `json:"reference"`
	Reports     map[string][]string `json:"reports"`
	Runbook     string              `json:"runbook"`
	Severity    Severity            `json:"severity"`
	Tests       []UnitTest          `json:"tests"`

	// Unique to rules
	DedupPeriodMinutes int      `json:"dedupPeriodMinutes"`
	LogTypes           []string `json:"logTypes"`
	Threshold          int      `json:"threshold"`
}

/***** Shared *****/

// The backend resource-processor uses enabled policies to scan modified resources.

// Here, we assume all policies fit in the 6MB response limit (no paging required)
// since only the fields we need for processing are returned in the response.
//
// TODO: add paging / merge into ListPolicies endpoint
//type GetEnabledDetectionsInput struct {
//	Type DetectionType `json:"type" validate:"required"`
//}
//
//type GetEnabledDetectionsOutput struct {
//	Items []EnabledDetection `json:"items"`
//}
//
//// Only includes the fields we need for backend processing
//type EnabledDetection struct {
//	Body string `json:"body"`
//	ID string `json:"id"`
//	OutputIDs []string `json:"outputIds"`
//	Reports map[string][]string `json:"reports"`
//	Tags []string `json:"tags"`
//	VersionID string `json:"versionId"`
//
//	// Defined only for cloud security policies
//	ResourceTypes []string `json:"resourceTypes"`
//	Severity      Severity `json:"severity"`
//	Suppressions  []string `json:"suppressions"`
//
//	// Defined only for log analysis rules
//	DedupPeriodMinutes int `json:"dedupPeriodMinutes"`
//}

type DeleteDetectionsInput struct {
	Entries []DeleteEntry `json:"entries" validate:"min=1,max=1000,dive"`
}

type DeleteEntry struct {
	ID string `json:"id" validate:"required"`
}
