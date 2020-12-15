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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolve(t *testing.T) {
	typeFoo := &ValueSchema{
		Type: TypeObject,
		Fields: []FieldSchema{
			{
				Name:        "fieldA",
				ValueSchema: ValueSchema{Type: TypeString},
			},
			{
				Name:        "fieldBar",
				ValueSchema: Ref("bar"),
			},
		},
	}
	typeBar := &ValueSchema{
		Type: TypeObject,
		Fields: []FieldSchema{
			{
				Name:        "fieldA",
				ValueSchema: ValueSchema{Type: TypeString},
			},
		},
	}
	unresolved := &Schema{
		Definitions: map[string]*ValueSchema{
			"foo": typeFoo,
		},
		Fields: []FieldSchema{
			{
				Name:        "fieldA",
				ValueSchema: ValueSchema{Type: TypeString},
			},
			{
				Name:        "fieldFoo",
				ValueSchema: Ref("foo"),
			},
		},
	}
	assert := require.New(t)
	r, err := Resolve(unresolved)
	assert.Error(err)
	assert.Nil(r)

	unresolved.Definitions["bar"] = typeBar

	actual, err := Resolve(unresolved)
	assert.NoError(err)
	expect := &ValueSchema{
		Type: TypeObject,
		Fields: []FieldSchema{
			{
				Name:        "fieldA",
				ValueSchema: ValueSchema{Type: TypeString},
			},
			{
				Name: "fieldFoo",
				ValueSchema: ValueSchema{
					Type: TypeObject,
					Fields: []FieldSchema{
						{
							Name:        "fieldA",
							ValueSchema: ValueSchema{Type: TypeString},
						},
						{
							Name:        "fieldBar",
							ValueSchema: *typeBar,
						},
					},
				},
			},
		},
	}
	assert.Equal(expect, actual)
}
