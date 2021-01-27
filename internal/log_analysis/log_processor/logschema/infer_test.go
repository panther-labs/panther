package logschema_test

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
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

func TestExport(t *testing.T) {
	assert := require.New(t)
	for _, entry := range registry.NativeLogTypes().Entries() {
		typ := reflect.TypeOf(entry.Schema())
		schema, err := logschema.InferTypeValueSchema(typ)
		assert.NoError(err, "schema export for %q should work", entry)
		data, err := yaml.Marshal(schema)
		assert.NoError(err, "schema export for %q YAML", entry)
		println(string(data))
	}
}
