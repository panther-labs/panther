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

	// Only include policies with a specific compliance status. Only applies to policies.
	ComplianceStatus models.ComplianceStatus `json:"complianceStatus" validate:"omitempty,oneof=PASS FAIL ERROR"`

	// Only include policies with or without auto-remediation enabled. Only applies to policies.
	HasRemediation *bool `json:"hasRemediation"`

	// Only include detections with the following ids
	IDs []string `json:"ids" validate:"max=1000"`

	// Only include policies which apply to one of these resource types. Only applies to policies.
	ResourceTypes []string `json:"resourceTypes" validate:"max=500,dive,required,max=500"`

	// Only include rules which apply to one of these log types. Only applies to rules.
	LogTypes []string `json:"logTypes" validate:"max=500,dive,required,max=500"`

	// Only include detections with the following type
	AnalysisTypes []DetectionType `json:"analysisTypes" validate:"omitempty,dive,oneof=RULE POLICY"`

	// Only include detections whose ID or display name contains this case-insensitive substring
	NameContains string `json:"nameContains" validate:"max=1000"`

	// Only include detections which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include detections with this severity
	Severity []models.Severity `json:"severity" validate:"dive,oneof=INFO LOW MEDIUM HIGH CRITICAL"`

	// Only include detections with all of these tags (case-insensitive)
	Tags []string `json:"tags" validate:"max=500,dive,required,max=500"`

	// Only include detections whose creator matches this user ID (which need not be a uuid)
	CreatedBy string `json:"createdBy"`

	// Only include detections which were last modified by this user ID
	LastModifiedBy string `json:"lastModifiedBy"`

	// If True, include only detections which were created by the system during the initial deployment
	// If False, include only detections where were NOT created by the system during the initial deployment
	InitialSet *bool `json:"initialSet"`

	// ----- Projection -----

	// Detection fields to return in the response (default: all)
	Fields []string `json:"fields" validate:"max=20,dive,required,max=100"`

	// ----- Sorting -----
	SortBy  string `json:"sortBy" validate:"omitempty,oneof=displayName enabled id lastModified severity"`
	SortDir string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`

	// ----- Paging -----
	PageSize int `json:"pageSize" validate:"min=0,max=1000"`
	Page     int `json:"page" validate:"min=0"`
}

type ListDetectionsOutput struct {
	Paging     Paging      `json:"paging"`
	Detections []Detection `json:"detections"`
}

type Detection struct {
	// Policy only
	AutoRemediationID         string                  `json:"autoRemediationId" validate:"max=1000"`
	AutoRemediationParameters map[string]string       `json:"autoRemediationParameters" validte:"max=500"`
	ComplianceStatus          models.ComplianceStatus `json:"complianceStatus"`
	ResourceTypes             []string                `json:"resourceTypes"`
	Suppressions              []string                `json:"suppressions" validate:"max=500,dive,required,max=1000"`

	// Rule only
	DedupPeriodMinutes int      `json:"dedupPeriodMinutes"`
	LogTypes           []string `json:"logTypes"`
	Threshold          int      `json:"threshold"`

	// Shared
	AnalysisType   DetectionType       `json:"analysisType"`
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
