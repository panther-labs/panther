package logtypesapi

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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
)

// GetSchema specifies the schema id and revision to retrieve.
// Zero Revision will get the latest revision of the schema record
type GetSchemaInput struct {
	Name     string `json:"name" validate:"required" description:"The schema id"`
	Revision int64  `json:"revision,omitempty" validate:"omitempty,min=1" description:"Schema record revision (0 means latest)"`
}

type GetSchemaOutput struct {
	Record *SchemaRecord `json:"record,omitempty" description:"The schema record (field omitted if an error occurred)"`
	Error  *APIError     `json:"error,omitempty" description:"An error that occurred while fetching the record"`
}

func (api *LogTypesAPI) GetSchema(ctx context.Context, input *GetSchemaInput) (*GetSchemaOutput, error) {
	record, err := api.Database.GetSchema(ctx, input.Name, input.Revision)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, NewAPIError(ErrNotFound, fmt.Sprintf("schema record %s not found", input.Name))
	}
	return &GetSchemaOutput{
		Record: record,
	}, nil
}

type SchemaRecord struct {
	Name      string    `json:"logType" dynamodbav:"logType" validate:"required" description:"The schema id"`
	Revision  int64     `json:"revision" validate:"required,min=1" description:"Schema record revision"`
	Release   string    `json:"release,omitempty" description:"Managed schema release version"`
	UpdatedAt time.Time `json:"updatedAt" description:"Last update timestamp of the record"`
	CreatedAt time.Time `json:"createdAt" description:"Creation timestamp of the record"`
	Managed   bool      `json:"managed,omitempty" description:"Schema is managed by Panther"`
	Disabled  bool      `json:"disabled,omitempty" dynamodbav:"IsDeleted"  description:"Log record is deleted"`
	// Updatable fields
	SchemaUpdate
}

type SchemaUpdate struct {
	Description  string `json:"description" description:"Log type description"`
	ReferenceURL string `json:"referenceURL" description:"A URL with reference docs for the schema"`
	Spec         string `json:"logSpec" dynamodbav:"logSpec" validate:"required" description:"The schema spec in YAML or JSON format"`
}

func (r *SchemaRecord) Describe() logtypes.Desc {
	return logtypes.Desc{
		Name:         r.Name,
		Description:  r.Description,
		ReferenceURL: r.ReferenceURL,
	}
}

func (r *SchemaRecord) IsManaged() bool {
	return r.Managed
}

func (r *SchemaRecord) IsCustom() bool {
	const prefix = customlogs.LogTypePrefix + "."
	return strings.HasPrefix(r.Name, prefix)
}
