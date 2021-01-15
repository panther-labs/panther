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

type ListDetectionsInput struct {
	// ----- Filtering -----
	// Only include policies with a specific compliance status
	// ONLY POLICIES
	ComplianceStatus models.ComplianceStatus `json:"complianceStatus" validate:"omitempty,oneof=PASS FAIL ERROR"`

	// Only include policies with or without auto-remediation enabled
	HasRemediation *bool `json:"hasRemediation"`

	// Only include policies which apply to one of these resource types
	// should we change this to just type?
	// ResourceTypes []string `json:"resourceTypes" validate:"max=500,dive,required,max=500"`

	// ONLY RULE
	// Only include rules which apply to one of these log types
	// LogTypes []string `json:"logTypes" validate:"max=500,dive,required,max=500"`
	Types []string `json:"types" validate:"max=500,dive,required,max=500"`

	// BOTH
	// Only include detections with the following type
	AnalysisTypes []DetectionType `json:"analysisTypes" validate:"omitempty,dive,oneof=RULE POLICY GLOBAL"`

	// Only include policies whose ID or display name contains this case-insensitive substring
	NameContains string `json:"nameContains" validate:"max=1000"`

	// Only include policies which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include policies with this severity
	Severity []models.Severity `json:"severity" validate:"dive,oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// Only include policies with all of these tags (case-insensitive)
	Tags []string `json:"tags" validate:"max=500,dive,required,max=500"`

	// If True, include only rules which were created by the system during the initial deployment
	// If False, include only rules where were NOT created by the system during the initial deployment
	InitialSet *bool `json:"initialSet"`
	// ----- Projection -----

	// Policy fields to return in the response (default: all)
	Fields []string `json:"fields" validate:"max=20,dive,required,max=100"`

	// ----- Sorting -----
	// Need to add displayName filtering
	SortBy  string `json:"sortBy" validate:"omitempty,oneof=displayName complianceStatus enabled id lastModified severity"`
	SortDir string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`

	// ----- Paging -----
	PageSize int `json:"pageSize" validate:"min=0,max=1000"`
	Page     int `json:"page" validate:"min=0"`

	// Only include policies whose creator matches this user ID (which need not be a uuid)
	CreatedBy string `json:"createdBy"`

	// Only include policies which were last modified by this user ID
	LastModifiedBy string `json:"lastModifiedBy"`
}

type ListDetectionsOutput struct {
	Paging     Paging      `json:"paging"`
	Detections []Detection `json:"detections"`
}

// TODO include policy & shared stuff
// Align this to also includue policy settings and type
type Detection struct {
	// Policy only
	AutoRemediationID         string                  `json:"autoRemediationId" validate:"max=1000"`
	AutoRemediationParameters map[string]string       `json:"autoRemediationParameters" validte:"max=500"`
	ComplianceStatus          models.ComplianceStatus `json:"complianceStatus"`
	Suppressions              []string                `json:"suppressions" validate:"max=500,dive,required,max=1000"`

	// Rule only
	DedupPeriodMinutes int `json:"dedupPeriodMinutes"`
	Threshold          int `json:"threshold"`

	// Shared
	AnalysisType   DetectionType       `json:"analysisType"`
	Types          []string            `json:"logTypes"`
	Body           string              `json:"body" validate:"required,max=100000"`
	CreatedAt      time.Time           `json:"createdAt"`
	CreatedBy      string              `json:"createdBy"`
	Description    string              `json:"description"`
	DisplayName    string              `json:"displayName" validate:"max=1000,excludesall='<>&\""`
	Enabled        bool                `json:"enabled"`
	ID             string              `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	LastModified   time.Time           `json:"lastModified"`
	LastModifiedBy string              `json:"lastModifiedBy"`
	OutputIDs      []string            `json:"outputIds" validate:"max=500,dive,required,max=5000"`
	Reference      string              `json:"reference" validate:"max=10000"`
	Reports        map[string][]string `json:"reports" validate:"max=500"`
	Runbook        string              `json:"runbook" validate:"max=10000"`
	Severity       models.Severity     `json:"severity" validate:"oneof=INFO LOW MEDIUM HIGH CRITICAL"`
	Tags           []string            `json:"tags" validate:"max=500,dive,required,max=1000"`
	Tests          []UnitTest          `json:"tests" validate:"max=500,dive"`
	VersionID      string              `json:"versionId"`
}
