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

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"
	"gopkg.in/go-playground/validator.v9"

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
	assert.Equal(`json:"remote_ips,omitempty"  panther:"ip" description:"remote ip addresses"`, string(goFields[0].Tag))
}

func TestAllowDeny(t *testing.T) {
	validate := validator.New()
	null.RegisterValidators(validate)
	assert := require.New(t)
	val, err := Resolve(&Schema{
		Fields: []FieldSchema{
			{
				Name: "foo",
				ValueSchema: ValueSchema{
					Type: TypeString,
					Validate: &Validation{
						Allow: []string{"Foo", "Foo|Bar", `"Foo"`, "`Foo`", "Bar,Baz", "Φου"},
					},
				},
			},
		},
	})
	assert.NoError(err)
	typ, err := val.GoType()
	assert.NoError(err)
	typ = typ.Elem()

	{
		x := reflect.New(typ).Interface()
		assert.NoError(jsoniter.UnmarshalFromString(`{"foo":"Bar"}`, x))
		assert.Error(validate.Struct(x), "Bar is denied")
	}
	{
		x := reflect.New(typ).Interface()
		assert.NoError(jsoniter.UnmarshalFromString(`{"foo":"Μπαρ"}`, x))
		assert.Error(validate.Struct(x), "Μπαρ is denied")
	}
	{
		x := reflect.New(typ).Interface()
		assert.NoError(jsoniter.UnmarshalFromString(`{"foo":"Foo"}`, x))
		err := validate.Struct(x)
		assert.NoError(err, "Foo passes")
	}
	{
		x := reflect.New(typ).Interface()
		assert.NoError(jsoniter.UnmarshalFromString(`{"foo":"Φου"}`, x))
		err := validate.Struct(x)
		assert.NoError(err, "Φου passes")
	}
	{
		x := reflect.New(typ).Interface()
		assert.NoError(jsoniter.UnmarshalFromString(`{"foo":"Foo|Bar"}`, x))
		err := validate.Struct(x)
		assert.NoError(err, "Foo|Bar allowed")
	}
	{
		x := reflect.New(typ).Interface()
		assert.NoError(jsoniter.UnmarshalFromString(`{"foo":"Bar,Baz"}`, x))
		err := validate.Struct(x)
		assert.NoError(err, "Bar,Baz allowed")
	}
	{
		x := reflect.New(typ).Interface()
		assert.NoError(jsoniter.UnmarshalFromString("{\"foo\":\"`Foo`\"}", x))
		err := validate.Struct(x)
		assert.NoError(err, "`Foo` allowed")
	}
	{
		x := reflect.New(typ).Interface()
		assert.NoError(jsoniter.UnmarshalFromString("{\"foo\":\"\\\"Foo\\\"\"}", x))
		err := validate.Struct(x)
		assert.NoError(err, `"Foo" allowed`)
	}
}
