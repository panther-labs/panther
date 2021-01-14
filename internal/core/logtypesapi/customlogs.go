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

	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/pkg/stringset"
)

// GetCustomLog gets a custom log record for the specified id and revision
func (api *LogTypesAPI) GetCustomLog(ctx context.Context, input *GetCustomLogInput) (*GetCustomLogOutput, error) {
	record, err := api.Database.GetCustomLog(ctx, input.LogType, input.Revision)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, NewAPIError(ErrNotFound, fmt.Sprintf("custom log record %s@%d not found", input.LogType, input.Revision))
	}
	return &GetCustomLogOutput{
		Result: record,
	}, nil
}

// GetCustomLogInput specifies the log type id and revision to retrieve.
// Zero Revision will get the latest revision of the log type record
type GetCustomLogInput struct {
	LogType  string `json:"logType" validate:"required,startswith=Custom." description:"The log type id"`
	Revision int64  `json:"revision,omitempty" validate:"omitempty,min=1" description:"Log record revision (0 means latest)"`
}
type GetCustomLogOutput struct {
	Result *CustomLogRecord `json:"record,omitempty" description:"The custom log record (field omitted if an error occurred)"`
	Error  *APIError        `json:"error,omitempty" description:"An error that occurred while fetching the record"`
}

// CustomLogRecord is a stored record for a custom log type
type CustomLogRecord struct {
	LogType   string    `json:"logType" validate:"required,startswith=Custom." description:"The log type id"`
	Revision  int64     `json:"revision" validate:"required,min=1" description:"Log record revision"`
	UpdatedAt time.Time `json:"updatedAt" description:"Last update timestamp of the record"`
	CustomLog
}

type CustomLog struct {
	Description  string `json:"description" description:"Log type description"`
	ReferenceURL string `json:"referenceURL" description:"A URL with reference docs for the log type"`
	LogSpec      string `json:"logSpec" validate:"required" description:"The log spec in YAML or JSON format"`
}

func (api *LogTypesAPI) PutCustomLog(ctx context.Context, input *PutCustomLogInput) (*PutCustomLogOutput, error) {
	id := customlogs.LogType(input.LogType)
	schema, err := buildSchema(id, &input.CustomLog)
	if err != nil {
		return nil, err
	}
	switch currentRevision := input.Revision; currentRevision {
	case 0:
		result, err := api.Database.CreateCustomLog(ctx, id, &input.CustomLog)
		if err != nil {
			return nil, err
		}
		if err := api.UpdateDataCatalog(ctx, input.LogType, nil, schema.Fields); err != nil {
			// The error will be shown to the user as a "ServerError"
			return nil, errors.Wrapf(err, "could not queue event for %q database update", input.LogType)
		}
		return &PutCustomLogOutput{Result: result}, nil
	default:
		current, err := api.Database.GetCustomLog(ctx, id, 0)
		if err != nil {
			return nil, err
		}
		if current == nil {
			return nil, NewAPIError(ErrNotFound, fmt.Sprintf("record %q was not found", id))
		}
		if current.Revision != currentRevision {
			return nil, NewAPIError(ErrRevisionConflict, fmt.Sprintf("record %q is not on revision %d", id, currentRevision))
		}

		currentSchema, err := buildSchema(id, &current.CustomLog)
		if err != nil {
			return nil, err
		}

		if err := api.checkUpdate(currentSchema, schema); err != nil {
			return nil, NewAPIError(ErrInvalidUpdate, fmt.Sprintf("schema update is not backwards compatible: %s", err))
		}
		result, err := api.Database.UpdateCustomLog(ctx, id, currentRevision, &input.CustomLog)
		if err != nil {
			return nil, err
		}
		if err := api.UpdateDataCatalog(ctx, input.LogType, currentSchema.Fields, schema.Fields); err != nil {
			// The error will be shown to the user as a "ServerError"
			return nil, errors.Wrapf(err, "could not queue event for %q database update", input.LogType)
		}
		return &PutCustomLogOutput{Result: result}, nil
	}
}

func (api *LogTypesAPI) checkUpdate(a, b *logschema.Schema) error {
	diff, err := logschema.Diff(a, b)
	if err != nil {
		return err
	}
	for i := range diff {
		c := &diff[i]
		if e := customlogs.CheckSchemaChange(c); e != nil {
			err = multierr.Append(err, e)
		}
	}
	return err
}

func buildSchema(id string, c *CustomLog) (*logschema.Schema, error) {
	desc := logtypes.Desc{
		Name:         id,
		Description:  c.Description,
		ReferenceURL: c.ReferenceURL,
	}

	// Pass strict validation rules for logtype.Desc
	desc.Fill()

	// This is checked again in `customlogs.Build` but we check here to provide the appropriate error code
	if err := desc.Validate(); err != nil {
		return nil, NewAPIError(ErrInvalidMetadata, err.Error())
	}
	schema := logschema.Schema{}
	if err := yaml.Unmarshal([]byte(c.LogSpec), &schema); err != nil {
		return nil, NewAPIError(ErrInvalidSyntax, err.Error())
	}
	if _, err := customlogs.Build(desc, &schema); err != nil {
		return nil, NewAPIError(ErrInvalidLogSchema, err.Error())
	}
	return &schema, nil
}

// nolint:lll
type PutCustomLogInput struct {
	LogType string `json:"logType" validate:"required,startswith=Custom." description:"The log type id"`
	// Revision is required when updating a custom log record.
	// If  is omitted a new custom log record will be created.
	Revision int64 `json:"revision,omitempty" validate:"omitempty,min=1" description:"Custom log record revision to update (if omitted a new record will be created)"`
	CustomLog
}

//nolint:lll
type PutCustomLogOutput struct {
	Result *CustomLogRecord `json:"record,omitempty" description:"The modified record (field is omitted if an error occurred)"`
	Error  *APIError        `json:"error,omitempty" description:"An error that occurred during the operation"`
}

func (api *LogTypesAPI) DelCustomLog(ctx context.Context, input *DelCustomLogInput) (*DelCustomLogOutput, error) {
	inUse, err := api.LogTypeInUse(ctx)
	if err != nil {
		return nil, err
	}

	if stringset.Contains(inUse, input.LogType) {
		return nil, NewAPIError(ErrInUse, fmt.Sprintf("log %s in use", input.LogType))
	}

	id, rev := customlogs.LogType(input.LogType), input.Revision
	if err := api.Database.DeleteCustomLog(ctx, id, rev); err != nil {
		return nil, err
	}
	if err := api.UpdateDataCatalog(ctx, input.LogType, nil, nil); err != nil {
		// The error will be shown to the user as a "ServerError"
		return nil, errors.Wrapf(err, "could not queue event for %q database update", input.LogType)
	}
	return &DelCustomLogOutput{}, nil
}

type DelCustomLogInput struct {
	LogType  string `json:"logType" validate:"required,startswith=Custom." description:"The log type id"`
	Revision int64  `json:"revision" validate:"min=1" description:"Log record revision"`
}

type DelCustomLogOutput struct {
	Error *APIError `json:"error,omitempty" description:"The delete record"`
}

func (api *LogTypesAPI) ListCustomLogs(ctx context.Context) (*ListCustomLogsOutput, error) {
	available, err := api.Database.IndexLogTypes(ctx)
	if err != nil {
		return nil, err
	}
	custom := available[:0]
	for _, logType := range available {
		if strings.HasPrefix(logType, customlogs.LogTypePrefix) {
			custom = append(custom, logType)
		}
	}
	records := make([]*CustomLogRecord, 0, len(custom))
	if len(custom) > 0 {
		records, err = api.Database.BatchGetCustomLogs(ctx, custom...)
		if err != nil {
			return nil, err
		}
	}
	return &ListCustomLogsOutput{CustomLogs: records}, nil
}

//nolint:lll
type ListCustomLogsOutput struct {
	CustomLogs []*CustomLogRecord `json:"customLogs" description:"Custom log records stored"`
	Error      *APIError          `json:"error,omitempty" description:"An error that occurred during the operation"`
}
