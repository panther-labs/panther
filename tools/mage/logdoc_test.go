package mage

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

	"github.com/stretchr/testify/assert"
)

func TestLogDocPrettyPrint(t *testing.T) {
	var colType, expected string

	// simple type
	colType = `string`
	expected = `string`
	assert.Equal(t, expected, prettyPrintType(colType, ""))

	// simple array
	colType = `array<string>`
	expected = `[string]`
	assert.Equal(t, expected, prettyPrintType(colType, ""))

	//  array of arrays
	colType = `array<array<string>>`
	expected = `[[string]]`
	assert.Equal(t, expected, prettyPrintType(colType, ""))

	//  array of maps
	colType = `array<map<string,string>>`
	expected = `[{<br>&nbps;&nbps;string:string<br>}]`
	assert.Equal(t, expected, prettyPrintType(colType, ""))

	// array of structs
	colType = `array<struct<foo:string,bar:string>>`
	expected = `[{<br>&nbps;&nbps;"foo":string,<br>&nbps;&nbps;"bar":string<br>}]`
	assert.Equal(t, expected, prettyPrintType(colType, ""))

	// simple map
	colType = `map<string,string>`
	expected = `{<br>&nbps;&nbps;string:string<br>}`
	assert.Equal(t, expected, prettyPrintType(colType, ""))

	// map of maps
	colType = `map<string,map<string,string>>`
	expected = `{<br>&nbps;&nbps;string:{<br>&nbps;&nbps;&nbps;&nbps;string:string<br>}<br>}` // nolint:lll
	assert.Equal(t, expected, prettyPrintType(colType, ""))

	// simple struct
	colType = `struct<foo:string,bar:string>`
	expected = `{<br>&nbps;&nbps;"foo":string,<br>&nbps;&nbps;"bar":string<br>}`
	assert.Equal(t, expected, prettyPrintType(colType, ""))

	// struct of array and map
	colType = `struct<foo:array<string>,bar:map<string,string>>`
	expected = `{<br>&nbps;&nbps;"foo":[string],<br>&nbps;&nbps;"bar":{<br>&nbps;&nbps;&nbps;&nbps;string:string<br>}<br>}` // nolint:lll
	assert.Equal(t, expected, prettyPrintType(colType, ""))

	// struct of struct
	colType = `struct<foo:struct<bar:string>>`
	expected = `{<br>&nbps;&nbps;"foo":{<br>&nbps;&nbps;&nbps;&nbps;"bar":string<br>}<br>}`
	assert.Equal(t, expected, prettyPrintType(colType, ""))

	// struct of struct of struct
	colType = `struct<foo:struct<bar:struct<zot:string>>>`
	expected = `{<br>&nbps;&nbps;"foo":{<br>&nbps;&nbps;&nbps;&nbps;"bar":{<br>&nbps;&nbps;&nbps;&nbps;&nbps;&nbps;"zot":string<br>}<br>}<br>}` // nolint:lll
	assert.Equal(t, expected, prettyPrintType(colType, ""))
}
