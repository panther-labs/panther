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

type DetectionType string

const (
	TypePolicy    DetectionType = "POLICY"
	TypeRule      DetectionType = "RULE"
	TypeGlobal    DetectionType = "GLOBAL"
	TypeDataModel DetectionType = "DATAMODEL"
	TypePack      DetectionType = "PACK"
)

type LambdaInput struct {
	// Shared
	BulkUpload       *BulkUploadInput     `json:"bulkUpload,omitempty"`
	ListDetections   *ListDetectionsInput `json:"listDetections,omitempty"`
	DeleteDetections *DeletePoliciesInput `json:"deleteDetections,omitempty"`

	// Globals
	CreateGlobal  *CreateGlobalInput  `json:"createGlobal,omitempty"`
	DeleteGlobals *DeleteGlobalsInput `json:"deleteGlobals,omitempty"`
	GetGlobal     *GetGlobalInput     `json:"getGlobal,omitempty"`
	ListGlobals   *ListGlobalsInput   `json:"listGlobals,omitempty"`
	UpdateGlobal  *UpdateGlobalInput  `json:"updateGlobal,omitempty"`

	// Policies (cloud security)
	CreatePolicy   *CreatePolicyInput   `json:"createPolicy,omitempty"`
	DeletePolicies *DeletePoliciesInput `json:"deletePolicies,omitempty"`
	GetPolicy      *GetPolicyInput      `json:"getPolicy,omitempty"`
	// TODO deprecate this endpoint in favor of ListDetections
	ListPolicies *ListPoliciesInput `json:"listPolicies,omitempty"`
	Suppress     *SuppressInput     `json:"suppress,omitempty"`
	TestPolicy   *TestPolicyInput   `json:"testPolicy,omitempty"`
	UpdatePolicy *UpdatePolicyInput `json:"updatePolicy,omitempty"`

	// Rules (log analysis)
	CreateRule  *CreateRuleInput  `json:"createRule,omitempty"`
	DeleteRules *DeleteRulesInput `json:"deleteRules,omitempty"`
	GetRule     *GetRuleInput     `json:"getRule,omitempty"`
	// TODO deprecate this endpoint in favor of ListDetections
	ListRules  *ListRulesInput  `json:"listRules,omitempty"`
	TestRule   *TestRuleInput   `json:"testRule,omitempty"`
	UpdateRule *UpdateRuleInput `json:"updateRule,omitempty"`

	// Data models (log analysis)
	CreateDataModel  *CreateDataModelInput  `json:"createDataModel,omitempty"`
	DeleteDataModels *DeleteDataModelsInput `json:"deleteDataModels,omitempty"`
	GetDataModel     *GetDataModelInput     `json:"getDataModel,omitempty"`
	ListDataModels   *ListDataModelsInput   `json:"listDataModels,omitempty"`
	UpdateDataModel  *UpdateDataModelInput  `json:"updateDataModel,omitempty"`

	// Detection Packs
	GetPack       *GetPackInput       `json:"getPack,omitempty"`
	EnumeratePack *EnumeratePackInput `json:"enumeratePack,omitempty"`
	ListPacks     *ListPacksInput     `json:"listPacks,omitempty"`
	PatchPack     *PatchPackInput     `json:"patchPack,omitempty"`
	PollPacks     *PollPacksInput     `json:"pollPacks,omitempty"`
}

type UnitTest struct {
	ExpectedResult bool   `json:"expectedResult"`
	Mocks          string `json:"mocks"`
	Name           string `json:"name" validate:"required"`
	Resource       string `json:"resource" validate:"required"`
}

type BulkUploadInput struct {
	Data   string `json:"data" validate:"required"` // base64-encoded zipfile
	UserID string `json:"userId" validate:"required"`
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

	TotalDataModels    int `json:"totalDataModels"`
	NewDataModels      int `json:"newDataModels"`
	ModifiedDataModels int `json:"modifiedDataModels"`
}
