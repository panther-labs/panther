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

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
)

// Resolver resolves a log type entry using the API
type Resolver struct {
	LogTypesAPI    *LogTypesAPILambdaClient
	NativeLogTypes logtypes.Finder
}

var _ logtypes.Resolver = (*Resolver)(nil)

// Resolve implements logtypes.Resolver
func (r *Resolver) Resolve(ctx context.Context, name string) (logtypes.Entry, error) {
	reply, err := r.LogTypesAPI.GetSchema(ctx, &GetSchemaInput{
		Name: name,
	})
	zap.L().Debug("log types API reply", zap.Any("reply", reply), zap.Error(err))
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
	record := reply.Record
	if record == nil {
		return nil, errors.New("unexpected empty result")
	}
	schema := logschema.Schema{}
	if err := yaml.Unmarshal([]byte(record.Spec), &schema); err != nil {
		return nil, errors.Wrap(err, "invalid schema YAML")
	}

	// Resolve native log types from their definition in go
	// TODO: only resolve the parser part of the entry once schema/parser split is done
	if p := schema.Parser; p != nil && p.Native != nil {
		entry := r.NativeLogTypes.Find(p.Native.Name)
		if entry == nil {
			return nil, errors.Errorf("failed to resolve native log type %q", name)
		}
		return entry, nil
	}
	schema.Description = record.Description
	schema.ReferenceURL = record.ReferenceURL

	return customlogs.Build(record.Name, &schema)
}
