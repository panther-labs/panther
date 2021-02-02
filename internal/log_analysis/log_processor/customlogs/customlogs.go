// Package customlogs provides log processing for user-defined logs
package customlogs

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
	"reflect"
	"strings"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs/customparser"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/preprocessors"
)

const LogTypePrefix = "Custom"

// LogType ensures a log type name is prefixed by LogTypePrefix
func LogType(name string) string {
	const prefix = LogTypePrefix + "."
	name = strings.TrimPrefix(name, prefix)
	return prefix + name
}

// Build validates the schema and metadata and builds a logtypes.Entry
func Build(name string, schema *logschema.Schema) (logtypes.Entry, error) {
	desc := logtypes.Desc{
		Name:         name,
		Description:  schema.Description,
		ReferenceURL: schema.ReferenceURL,
	}
	desc.Fill()
	if err := desc.Validate(); err != nil {
		return nil, errors.Wrap(err, "log type metadata validation failed")
	}

	if err := logschema.ValidateSchema(schema); err != nil {
		return nil, err
	}
	valueSchema, err := logschema.Resolve(schema)
	if err != nil {
		return nil, err
	}

	typ, err := valueSchema.GoType()
	if err != nil {
		return nil, err
	}
	eventType := typ.Elem()
	eventSchema, err := pantherlog.BuildEventTypeSchema(eventType)
	if err != nil {
		return nil, err
	}
	preProcessor, err := buildPreprocessor(schema.Parser)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build preprocessor")
	}
	entry, err := logtypes.Config{
		Name:         name,
		Description:  desc.Description,
		ReferenceURL: desc.ReferenceURL,
		Schema:       reflect.New(eventSchema).Interface(),
		NewParser: &customparser.Factory{
			LogType:      name,
			EventSchema:  eventType,
			PreProcessor: preProcessor,
			API:          pantherlog.ConfigJSON(),
			Builder:      pantherlog.ResultBuilder{},
			Validate:     pantherlog.ValidateStruct,
		},
	}.BuildEntry()
	if err != nil {
		return nil, errors.WithMessage(err, "log type entry generation failed")
	}
	return entry, nil
}

func buildPreprocessor(parser *logschema.Parser) (preprocessors.Interface, error) {
	switch {
	case parser == nil:
		return preprocessors.Nop(), nil
	case parser.FastMatch != nil:
		return parser.FastMatch.BuildPreprocessor()
	case parser.CSV != nil:
		return parser.CSV.BuildPreprocessor()
	case parser.Regex != nil:
		return parser.Regex.BuildPreprocessor()
	default:
		return preprocessors.Nop(), nil
	}
}
