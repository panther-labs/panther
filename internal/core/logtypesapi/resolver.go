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
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
)

// Resolver resolves a custom log type using the API
type Resolver struct {
	LogTypesAPI *LogTypesAPILambdaClient
}

var _ logtypes.Resolver = (*Resolver)(nil)

// Resolve implements logtypes.Resolver
func (r *Resolver) Resolve(ctx context.Context, name string) (logtypes.Entry, error) {
	if !strings.HasPrefix(name, customlogs.LogTypePrefix) {
		return nil, nil
	}
	reply, err := r.LogTypesAPI.GetCustomLog(ctx, &GetCustomLogInput{
		LogType:  name,
		Revision: 0,
	})
	zap.L().Debug("logtypesapi reply", zap.Any("reply", reply), zap.Error(err))
	if err != nil {
		return nil, err
	}
	if reply.Error != nil {
		if reply.Error.Code == ErrNotFound {
			// Record was not found in DB.
			return nil, nil
		}
		return nil, NewAPIError(reply.Error.Code, reply.Error.Message)
	}
	record := reply.Result
	if record == nil {
		return nil, errors.New("unexpected empty result")
	}
	schema := logschema.Schema{}
	if err := yaml.Unmarshal([]byte(record.LogSpec), &schema); err != nil {
		return nil, errors.Wrap(err, "invalid schema YAML")
	}
	desc := logtypes.Desc{
		Name:         record.LogType,
		Description:  record.Description,
		ReferenceURL: record.ReferenceURL,
	}
	entry, err := customlogs.Build(desc, &schema)
	if err != nil {
		return nil, errors.Wrap(err, "invalid schema")
	}
	return entry, nil
}
