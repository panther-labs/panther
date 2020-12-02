package logschema

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

func TestFieldNameGo(t *testing.T) {
	assert := require.New(t)
	assert.Equal("Foo", fieldNameGo("foo"))
	assert.Equal("Foo", fieldNameGo("_foo"))
	assert.Equal("Foo", fieldNameGo("φδσφδσαfoo"))
	assert.Equal("Foo_bar", fieldNameGo("foo.bar"))
	assert.Equal("Foo_bar", fieldNameGo("foo:bar"))
	assert.Equal("Field_01", fieldNameGo("01"))
}

func TestArrayIndicators(t *testing.T) {
	schemaFields := []FieldSchema{
		{
			Name:        "remote_ips",
			Description: "remote ip addresses",
			ValueSchema: ValueSchema{
				Type: TypeArray,
				Element: &ValueSchema{
					Type: TypeString,
					Indicators: []string{
						"ip",
					},
				},
			},
		},
	}
	goFields, err := objectFields(schemaFields)
	assert := require.New(t)
	assert.NoError(err)
	assert.Equal(1, len(goFields))
	assert.Equal(reflect.TypeOf([]null.String{}), goFields[0].Type)
	assert.Equal(`json:"remote_ips,omitempty" panther:"ip" description:"remote ip addresses"`, string(goFields[0].Tag))
}
