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

type CreateGlobalInput = UpdateGlobalInput

type DeleteGlobalsInput = DeletePoliciesInput

type GetGlobalInput struct {
	ID        string `json:"id" validate:"required,max=1000"`
	VersionID string `json:"versionId" validate:"omitempty,len=32"`
}

type ListGlobalsInput struct {
	// JSON field names (passed to Dynamo as a projection). For example,
	// ["id", "lastModified", "tags"]
	Fields []string `json:"fields" validate:"max=15,dive,required,max=100"`

	SortDir  string `json:"sortDir" validate:"omitempty,oneof=ascending descending"`
	PageSize int    `json:"pageSize" validate:"min=0,max=1000"`
	Page     int    `json:"page" validate:"min=0"`
}

type ListGlobalsOutput struct {
	Paging  Paging   `json:"paging"`
	Globals []Global `json:"globals"`
}

type UpdateGlobalInput struct {
	Body        string   `json:"body" validate:"required,max=100000"`
	Description string   `json:"description" validate:"max=10000"`
	ID          string   `json:"id" validate:"required,max=1000,excludesall='<>&\""`
	Tags        []string `json:"tags" validate:"max=500,dive,required,max=1000"`
	UserID      string   `json:"userId" validate:"required"`
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
