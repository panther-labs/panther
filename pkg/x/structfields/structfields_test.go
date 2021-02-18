package structfields

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
)

func TestFormatTag(t *testing.T) {
	typ := reflect.StructOf([]reflect.StructField{
		{
			Name: "Foo",
			Type: reflect.TypeOf(""),
			Tag:  reflect.StructTag(FormatTag("description", `The "foo" `+"` field")),
		},
	})
	d := typ.Field(0).Tag.Get("description")
	assert := require.New(t)
	assert.Equal("The \"foo\" \u0060 field", d)
}
