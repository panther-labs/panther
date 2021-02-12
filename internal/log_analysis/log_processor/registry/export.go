package registry

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
	"net/url"
	"reflect"
	"strings"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
)

// ExportSchemas converts all native log types as schema specs.
// It is used to export the log types defined in go to the log-analysis repository
// It omits fields whose name has a `p_` prefix
func ExportSchemas() (map[string]*logschema.Schema, error) {
	native := NativeLogTypes()
	out := make(map[string]*logschema.Schema)
	for _, entry := range native.Entries() {
		eventType := reflect.TypeOf(entry.Schema())
		valueSchema, err := logschema.InferTypeValueSchema(eventType)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to infer value schema for %s", entry)
		}
		if valueSchema.Type != logschema.TypeObject {
			return nil, errors.Errorf("invalid value schema %s for %s", valueSchema.Type, entry)
		}

		desc := entry.Describe()
		// Avoid invalid reference URLs in export
		if u, err := url.Parse(desc.ReferenceURL); err != nil || u.Scheme == "" {
			desc.ReferenceURL = ""
		}
		schema := logschema.Schema{
			Parser: &logschema.Parser{
				Native: &logschema.NativeParser{
					Name: desc.Name,
				},
			},
			Schema:       desc.Name,
			Description:  desc.Description,
			ReferenceURL: desc.ReferenceURL,
			Fields:       make([]logschema.FieldSchema, 0, len(valueSchema.Fields)),
		}
		for _, f := range valueSchema.Fields {
			// skip `p_` fields added by Panther
			if strings.HasPrefix(f.Name, `p_`) {
				continue
			}
			schema.Fields = append(schema.Fields, f)
		}
		out[desc.Name] = &schema
	}
	return out, nil
}
