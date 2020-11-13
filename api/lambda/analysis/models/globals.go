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

type CreateGlobalInput = UpdateGlobalInput

type DeleteGlobalsInput = DeleteDetectionsInput

type GetGlobalInput struct {
	GlobalID  string `json:"globalId" validate:"required"`
	VersionID string `json:"versionId"`
}

type ListGlobalsInput struct {
	// JSON field names (passed to Dynamo as a projection). For example,
	// ["id", "lastModified", "tags"]
	Fields []string `json:"fields" validate:"omitempty,dive,required"`

	SortDir  string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`
	PageSize int    `json:"pageSize" validate:"min=0"`
	Page     int    `json:"page" validate:"min=0"`
}

type ListGlobalsOutput struct {
	Paging  Paging   `json:"paging"`
	Globals []Global `json:"globals"`
}

type UpdateGlobalInput struct {
	CoreEntryUpdate
}

type Global struct {
	CoreEntry
}
