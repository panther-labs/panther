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
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/pkg/genericapi"
)

// GetCustomLog gets a custom log record for the specified id and revision
func (api *LogTypesAPI) GetCustomLog(ctx context.Context, input *GetCustomLogInput) (*GetCustomLogOutput, error) {
	record, err := api.Database.GetCustomLog(ctx, input.LogType, input.Revision)
	if err != nil {
		return &GetCustomLogOutput{
			Error: WrapAPIError(err),
		}, nil
	}
	if record == nil {
		return &GetCustomLogOutput{
			Error: NewAPIError(ErrNotFound, fmt.Sprintf("custom log record %s@%d not found", input.LogType, input.Revision)),
		}, nil
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
	Result *CustomLogRecord `json:"record,omitempty" validate:"required_without=Error" description:"The custom log record"`
	Error  *APIError        `json:"error,omitempty" validate:"required_without=Result" description:"An error that occurred"`
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
	ReferenceURL string `json:"referenceURL" description:"A URL with reference docs for the logtype"`
	LogSpec      string `json:"logSpec" validate:"required" description:"The log spec in YAML or JSON format"`
}

func (api *LogTypesAPI) PutCustomLog(ctx context.Context, input *PutCustomLogInput) (*PutCustomLogOutput, error) {
	id := customlogs.LogType(input.LogType)
	desc := logtypes.Desc{
		Name:         id,
		Description:  input.Description,
		ReferenceURL: input.ReferenceURL,
	}

	// Pass strict validation rules for logtype.Desc
	desc.Fill()

	// This is checked again in `customlogs.Build` but we check here to provide the appropriate error code
	if err := desc.Validate(); err != nil {
		return &PutCustomLogOutput{
			Error: NewAPIError("InvalidMetadata", err.Error()),
		}, nil
	}
	schema := logschema.Schema{}
	if err := yaml.Unmarshal([]byte(input.LogSpec), &schema); err != nil {
		return &PutCustomLogOutput{
			Error: NewAPIError("InvalidSyntax", err.Error()),
		}, nil
	}
	if _, err := customlogs.Build(desc, &schema); err != nil {
		return &PutCustomLogOutput{
			Error: NewAPIError("InvalidLogSchema", err.Error()),
		}, nil
	}
	if rev := input.Revision; rev > 0 {
		return &PutCustomLogOutput{
			Error: NewAPIError("Unsupported", "updates are not supported yet."),
		}, nil
	}
	result, err := api.Database.CreateCustomLog(ctx, id, &input.CustomLog)
	if err != nil {
		return &PutCustomLogOutput{
			Error: WrapAPIError(err),
		}, nil
	}
	return &PutCustomLogOutput{Result: result}, nil
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
	Result *CustomLogRecord `json:"record,omitempty" validate:"required_without=Error" description:"The modified record"`
	Error  *APIError        `json:"error,omitempty" validate:"required_without=Result" description:"An error that occurred during the operation"`
}

func (api *LogTypesAPI) DelCustomLog(ctx context.Context, input *DelCustomLogInput) (*DelCustomLogOutput, error) {
	inUse, err := api.getLogTypesInUse()
	if err != nil {
		return &DelCustomLogOutput{
			Error: WrapAPIError(err),
		}, nil
	}

	for _, logType := range inUse {
		if logType == input.LogType {
			return &DelCustomLogOutput{
				Error: NewAPIError(ErrInUse, fmt.Sprintf("log %s in use", input.LogType)),
			}, nil
		}
	}

	id, rev := customlogs.LogType(input.LogType), input.Revision
	if err := api.Database.DeleteCustomLog(ctx, id, rev); err != nil {
		return &DelCustomLogOutput{
			Error: WrapAPIError(err),
		}, nil
	}
	return &DelCustomLogOutput{}, nil
}

type DelCustomLogInput struct {
	LogType  string `json:"logType" validate:"required,startswith=Custom." description:"The log type id"`
	Revision int64  `json:"revision" validate:"min=1" description:"Log record revision"`
}
type DelCustomLogOutput struct {
	Error *APIError `json:"error,omitempty" validate:"required_without=Result" description:"The delete record"`
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
			return &ListCustomLogsOutput{
				Error: WrapAPIError(err),
			}, nil
		}
	}
	return &ListCustomLogsOutput{
		CustomLogs: records,
	}, nil
}

func (api *LogTypesAPI) getLogTypesInUse() ([]string, error) {
	// we need to update the cache
	input := &models.LambdaInput{
		ListIntegrations: &models.ListIntegrationsInput{},
	}
	var integrations []*models.SourceIntegration
	const sourcesAPILambda = "panther-source-api"
	if err := genericapi.Invoke(api.LambdaClient, sourcesAPILambda, input, &integrations); err != nil {
		return nil, errors.Wrap(err, "failed to retrieve existing integrations")
	}
	var logTypes []string
	for _, output := range integrations {
		logTypes = append(logTypes, output.RequiredLogTypes()...)
	}
	return logTypes, nil
}

//nolint:lll
type ListCustomLogsOutput struct {
	CustomLogs []*CustomLogRecord `json:"customLogs" validate:"required,min=0" description:"Custom log records stored"`
	Error      *APIError          `json:"error,omitempty" validate:"required_without=Result" description:"An error that occurred during the operation"`
}
