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

type LambdaInput struct {
	// Shared
	BulkUpload       *BulkUploadInput       `json:"bulkUpload"`
	DeleteDetections *DeleteDetectionsInput `json:"deleteDetections"`

	// Globals
	CreateGlobal  *CreateGlobalInput  `json:"createGlobal"`
	DeleteGlobals *DeleteGlobalsInput `json:"deleteGlobals"`
	GetGlobal     *GetGlobalInput     `json:"getGlobal"`
	ListGlobals   *ListGlobalsInput   `json:"listGlobals"`
	UpdateGlobal  *UpdateGlobalInput  `json:"updateGlobal"`

	// Policies (cloud security)
	CreatePolicy *CreatePolicyInput `json:"createPolicy"`
	GetPolicy    *GetPolicyInput    `json:"getPolicy"`
	ListPolicies *ListPoliciesInput `json:"listPolicies"`
	Suppress     *SuppressInput     `json:"suppress"`
	TestPolicy   *TestPolicyInput   `json:"testPolicy"`
	UpdatePolicy *UpdatePolicyInput `json:"updatePolicy"`

	// Rules (log analysis)
	CreateRule *CreateRuleInput `json:"createRule"`
	GetRule    *GetRuleInput    `json:"getRule"`
	ListRules  *ListRulesInput  `json:"listRules"`
	TestRule   *TestRuleInput   `json:"testRule"`
	UpdateRule *UpdateRuleInput `json:"updateRule"`

	// Data models (log analysis)
	//CreateDataModel *CreateDataModelInput `json:"createDataModel"`
	//GetDataModel    *GetDataModelInput    `json:"getDataModel"`
	//ListDataModels  *ListDataModelsInput  `json:"listDataModels"`
	//UpdateDataModel *UpdateDataModelInput `json:"updateDataModel"`
}

// All detection types (global/data-model/policy/rule/query) have these fields in common
type CoreEntry struct {
	Body           string    `json:"body"` // not required for data models
	CreatedAt      time.Time `json:"createdAt" validate:"required"`
	CreatedBy      string    `json:"createdBy" validate:"uuid4"`
	Description    string    `json:"description"`
	ID             string    `json:"id" validate:"required"`
	LastModified   time.Time `json:"lastModified" validate:"required"`
	LastModifiedBy string    `json:"lastModifiedBy" validate:"uuid4"`
	Tags           []string  `json:"tags" validate:"omitempty,dive,required"`
	VersionID      string    `json:"versionId" validate:"required"`
}

// Creating or updating any item supports these fields
type CoreEntryUpdate struct {
	Body        string   `json:"body" validate:"required"`
	Description string   `json:"description"`
	ID          string   `json:"id" validate:"required"`
	Tags        []string `json:"tags" validate:"omitempty,dive,required"`
	UserID      string   `json:"userId" validate:"uuid4"`
}

// Python rules and policies share these fields
type PythonDetection struct {
	DisplayName string              `json:"displayName"`
	Enabled     bool                `json:"enabled"`
	OutputIDs   []string            `json:"outputIds" validate:"omitempty,dive,required"`
	Reference   string              `json:"reference"`
	Reports     map[string][]string `json:"reports"`
	Runbook     string              `json:"runbook"`
	Severity    models.Severity     `json:"severity" validate:"oneof=INFO LOW MEDIUM HIGH CRITICAL"`
	Tests       []UnitTest          `json:"tests" validate:"dive"`
}

type UnitTest struct {
	ExpectedResult bool   `json:"expectedResult"`
	Name           string `json:"name" validate:"required"`
	Resource       string `json:"resource" validate:"required"`
}

type BulkUploadInput struct {
	Data   string `json:"data" validate:"required"` // base64-encoded zipfile
	UserID string `json:"userId" validate:"uuid4"`
}

type BulkUploadOutput struct {
	TotalPolicies    int `json:"totalPolicies"`
	NewPolicies      int `json:"newPolicies"`
	ModifiedPolicies int `json:"modifiedPolicies"`

	TotalRules    int `json:"totalRules"`
	NewRules      int `json:"newRules"`
	ModifiedRules int `json:"modifiedRules"`

	TotalGlobals    int `json:"totalGlobals"`
	NewGlobals      int `json:"newGlobals"`
	ModifiedGlobals int `json:"modifiedGlobals"`
}

type DeleteDetectionsInput struct {
	Entries []DeleteEntry `json:"entries" validate:"min=1,max=1000,dive"`
}

type DeleteEntry struct {
	ID string `json:"id" validate:"required"`
}
