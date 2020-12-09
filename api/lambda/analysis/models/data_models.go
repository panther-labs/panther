package models

import "time"

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

type CreateDataModelInput = UpdateDataModelInput

type DeleteDataModelsInput = DeletePoliciesInput

type GetDataModelInput struct {
	ID        string `json:"id" validate:"required,max=1000"`
	VersionID string `json:"versionId" validate:"omitempty,len=32"`
}

type ListDataModelsInput struct {
	// ----- Filtering -----
	// Only include data models which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include data models whose ID contains this substring (case-insensitive)
	NameContains string `json:"nameContains"`

	// Only include data models which apply to one of these log types
	LogTypes []string `json:"logTypes" validate:"dive,required,max=500"`

	// ----- Sorting -----
	SortBy  string `json:"sortBy" validate:"omitempty,oneof=enabled id lastModified logTypes"`
	SortDir string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`

	// ----- Paging -----
	PageSize int `json:"pageSize" validate:"min=0,max=1000"`
	Page     int `json:"page" validate:"min=0"`
}

type ListDataModelsOutput struct {
	Models []DataModel `json:"models"`
	Paging Paging      `json:"paging"`
}

type UpdateDataModelInput struct {
	Body        string             `json:"body" validate:"omitempty,max=100000"` // not required
	Description string             `json:"description" validate:"max=10000"`
	DisplayName string             `json:"displayName" validate:"max=1000,excludesall='<>&\""`
	Enabled     bool               `json:"enabled"`
	ID          string             `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	LogTypes    []string           `json:"logTypes" validate:"len=1,dive,required,max=500"` // for now, only one logtype allowed
	Mappings    []DataModelMapping `json:"mappings" validate:"min=1,max=500,dive"`
	UserID      string             `json:"userId" validate:"required"`
}

type DataModel struct {
	Body           string             `json:"body"`
	CreatedAt      time.Time          `json:"createdAt"`
	CreatedBy      string             `json:"createdBy"`
	Description    string             `json:"description"`
	DisplayName    string             `json:"displayName"`
	Enabled        bool               `json:"enabled"`
	ID             string             `json:"id"`
	LastModified   time.Time          `json:"lastModified"`
	LastModifiedBy string             `json:"lastModifiedBy"`
	LogTypes       []string           `json:"logTypes"`
	Mappings       []DataModelMapping `json:"mappings"`
	VersionID      string             `json:"versionId"`
}

type DataModelMapping struct {
	Name   string `json:"name" validate:"required,max=1000"`
	Path   string `json:"path" validate:"required_without=Method,max=1000"`
	Method string `json:"method" validate:"required_without=Path,max=1000"`
}
