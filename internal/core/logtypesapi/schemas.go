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
)

// GetSchemaInput specifies the schema id and revision to retrieve.
// Zero Revision will get the latest revision of the schema record
type GetSchemaInput struct {
	Name     string `json:"name" validate:"required" description:"The schema id"`
	Revision int64  `json:"revision,omitempty" validate:"omitempty,min=1" description:"Schema record revision (0 means latest)"`
}

type GetSchemaOutput struct {
	Record *SchemaRecord `json:"record,omitempty" description:"The schema record (field omitted if an error occurred)"`
	Error  *APIError     `json:"error,omitempty" description:"An error that occurred while fetching the record"`
}

// GetSchema gets a schema record
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

// SchemaRecord describes a stored schema.
//
// A SchemaRecord can either be managed or user-defined.
// Managed schema records have their Managed field set to `true` and include a version tag in Release field.
// User-defined schema records have Managed and Release fields missing.
type SchemaRecord struct {
	// For compatibility we use 'logType' as the DDB field name
	Name      string    `json:"logType" dynamodbav:"logType" validate:"required" description:"The schema id"`
	Revision  int64     `json:"revision" validate:"required,min=1" description:"Schema record revision"`
	Release   string    `json:"release,omitempty" description:"Managed schema release version"`
	UpdatedAt time.Time `json:"updatedAt" description:"Last update timestamp of the record"`
	CreatedAt time.Time `json:"createdAt" description:"Creation timestamp of the record"`
	Managed   bool      `json:"managed,omitempty" description:"Schema is managed by Panther"`
	// For compatibility we use 'IsDeleted' as the DDB field name
	Disabled bool `json:"disabled,omitempty" dynamodbav:"IsDeleted"  description:"Log record is deleted"`
	// Updatable fields
	SchemaUpdate
}

// SchemaUpdate contains the user-updatable fields of a schema record.
type SchemaUpdate struct {
	Description  string `json:"description" description:"Log type description"`
	ReferenceURL string `json:"referenceURL" description:"A URL with reference docs for the schema"`
	// For compatibility we use 'logSpec' as the JSON and DDB field names
	Spec string `json:"logSpec" dynamodbav:"logSpec" validate:"required" description:"The schema spec in YAML or JSON format"`
}

// IsManaged checks if a schema record is managed by Panther
func (r *SchemaRecord) IsManaged() bool {
	return r.Managed
}

// IsCustom checks the schema record name to determine if it is for a user-defined schema
func (r *SchemaRecord) IsCustom() bool {
	const prefix = customlogs.LogTypePrefix + "."
	return strings.HasPrefix(r.Name, prefix)
}
