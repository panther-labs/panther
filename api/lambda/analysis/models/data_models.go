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

type CreateDataModelInput = UpdateDataModelInput

type GetDataModelInput struct {
	DataModelID string `json:"dataModelId" validate:"required"`
	VersionID   string `json:"versionId"`
}

type ListDataModelsInput struct {
	// ----- Filtering -----
	// Only include data models which are enabled or disabled
	Enabled *bool `json:"enabled"`

	// Only include data models whose ID contains this substring (case-insensitive)
	NameContains string `json:"nameContains"`

	// Only include data models which apply to one of these log types
	LogTypes []string `json:"logTypes" validate:"omitempty,dive,required"`

	// ----- Sorting -----
	SortBy  string `json:"sortBy" validate:"omitempty,oneof=enabled id lastModified logTypes"`
	SortDir string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`

	// ----- Paging -----
	PageSize int `json:"pageSize" validate:"min=0"`
	Page     int `json:"page" validate:"min=0"`
}

type ListDataModelsOutput struct {
	DataModels []DataModel `json:"dataModels"`
	Paging     Paging      `json:"paging"`
}

type UpdateDataModelInput struct {
	Body        string             `json:"body"` // not required
	Description string             `json:"description"`
	Enabled     bool               `json:"enabled"`
	ID          string             `json:"id" validate:"required"`
	LogTypes    []string           `json:"logTypes" validate:"omitempty,dive,required"`
	Mappings    []DataModelMapping `json:"mappings" validate:"min=1,dive"`
	UserID      string             `json:"userId" validate:"uuid4"`
}

type DataModel struct {
	CoreEntry

	Enabled  bool               `json:"enabled"`
	LogTypes []string           `json:"logTypes"`
	Mappings []DataModelMapping `json:"mappings"`
}

type DataModelMapping struct {
	Name   string `json:"name" validate:"required"`
	Field  string `json:"field"`
	Method string `json:"method"`
}
