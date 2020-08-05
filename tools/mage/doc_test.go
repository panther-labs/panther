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
	"github.com/stretchr/testify/require"
)

const logType, colName = "SomeParserType.SomeParser", "someColumn"

func TestHeaderAnchor(t *testing.T) {
	mustHeader := func(title string) string {
		result, err := headerAnchor(title)
		require.NoError(t, err, title)
		return result
	}

	// These examples were generated from gitbooks itself by pushing test docs.
	assert.Equal(t, "aws-s-3-serveraccess", mustHeader("AWS.S3ServerAccess"))
	assert.Equal(t, "s3-server", mustHeader("S3 Server"))
	assert.Equal(t, "s-3-server", mustHeader("S3Server"))

	assert.Equal(t, "3-5", mustHeader("3.5"))
	assert.Equal(t, "a-1-b", mustHeader("A1B"))
	assert.Equal(t, "a-1-b", mustHeader(`"A1B"`))
	assert.Equal(t, "12345", mustHeader("12345"))
	assert.Equal(t, "a-1-b-2-c-3", mustHeader("A-1-B-2-C-3"))
	assert.Equal(t, "abc-123-def", mustHeader("ABC 123 DEF"))
	assert.Equal(t, "3s", mustHeader("3S"))
	assert.Equal(t, "s3", mustHeader("S3"))
	assert.Equal(t, "a-0-a-b-1-b-c-2-c-d-3-d-e-0-e", mustHeader("A0A B1B C2C D3D E0E"))
	assert.Equal(t, "f-10-fg-11-gh-12-hi-13-i", mustHeader("F10FG11GH12HI13I"))
	assert.Equal(t, "000aa-000-aa-000-aa-000-aa-000-aa000", mustHeader("000AA000AA000AA000AA000AA000"))

	assert.Equal(t, "aa-11-bb-22-cc-33-dd", mustHeader("AA11BB22CC33DD"))
	assert.Equal(t, "aa-11bb-22-cc-33-dd", mustHeader("AA 11BB22CC33DD"))
	assert.Equal(t, "aa11-bb-22-cc-33-dd", mustHeader("AA11 BB22CC33DD"))
	assert.Equal(t, "aa-11-bb-22cc-33-dd", mustHeader("AA11BB 22CC33DD"))
	assert.Equal(t, "aa-11-bb22-cc-33-dd", mustHeader("AA11BB22 CC33DD"))
	assert.Equal(t, "aa-11-bb-22-cc-33dd", mustHeader("AA11BB22CC 33DD"))
	assert.Equal(t, "aa-11-bb-22-cc33-dd", mustHeader("AA11BB22CC33 DD"))

	assert.Equal(t, "a-1-b-2-c-3-d-4", mustHeader("-A-1-b-2-c-3-d-4-"))
	assert.Equal(t, "a-1-b-2-c-3-d-4", mustHeader("A--1--B--2--C--3--D--4"))
	assert.Equal(t, "a-1-b-2-c-3-d-4", mustHeader("A - 1 - B - 2 - C - 3 - D - 4"))
	assert.Equal(t, "a-1-b-2-c-3-d-4", mustHeader("A..1..B..2..C..3..D..4"))

	assert.Equal(t, "usd-and-a", mustHeader(`!@#$%^&A()()()=-`))
	assert.Equal(t, "a-or-less-than-greater-than", mustHeader(`-:A:{}[]|\/-<>?`))

	assert.Equal(t, "undefined", mustHeader(""))
	assert.Equal(t, "undefined", mustHeader("-"))
	assert.Equal(t, "undefined", mustHeader("--"))
	assert.Equal(t, "undefined", mustHeader("."))
	assert.Equal(t, "undefined", mustHeader("%..%"))
}

func TestHeaderAnchorErrors(t *testing.T) {
	// When numbers mix with single characters and/or special characters, things get weird.
	//
	// Here, number dashing seems to alternate:
	//   "A1B2C3D4E5F6G7H8I9J0" => "a-1-b2c-3-d4e-5-f6g-7-h8i-9-j0"
	//   "A0A0A0A" => "a-0-a0a-0-a"
	//   "A00A00A00A" => "a-00-a00a-00-a"
	//   "000A000A000A000A000A000" => "000a-000-a000a-000-a000a000"
	//   "A0B0C0D0" => "a-0-b0c-0-d0"
	//   "0A0B0C0D" => "0a-0-b0c-0-d"
	//   "0A0A0A0A0A0" => "0a-0-a0a-0-a0a0"
	//
	// But even that pattern changes if special characters are introduced:
	//   "A1B2C3D4" => "a-1-b2c-3-d4"
	//   "A.1B2C3D4" => "a-1-b2c-3-d4"
	//   "A 1B2C3D4" -> "a-1b-2-c3d4"
	//   "A1.B2C3D4" => "a-1-b-2-c3d4"
	//   "A1 B2C3D4" => "a1-b-2-c3d4"
	//   "A1B.2C3D4" => "a-1-b-2-c3d4"
	//   "A1B 2C3D4" => "a-1-b-2c-3-d4"
	//   "A1B2.C3D4" => "a-1-b2-c-3-d4"
	//   "A1B2 C3D4" => "a-1-b2-c-3-d4"
	//   "A1B2C.3D4" => "a-1-b2c-3-d4"
	//   "A1B2C 3D4" => "a-1-b2c-3d4"
	//   "A1B2C3.D4" => "a-1-b2c-3-d4"
	//   "A1B2C3 D4" => "a-1-b2c3-d4"
	//   "A1B2C3D.4" => "a-1-b2c-3-d-4"
	//   "A1B2C3D 4" => "a-1-b2c-3-d-4"
	//
	// Generally, a special character is like a space, but not in these cases:
	//   "S3.Server" => "s-3-server"
	//   "AA.11BB22CC" => "aa-11-bb-22-cc" ("AA 11BB22CC" would be "aa-11bb-22-cc")
	//
	// Unless we are given or can figure out the true link generation algorithm,
	// we just give up and return errors for these cases.
	mustError := func(title string) {
		result, err := headerAnchor(title)
		assert.Equal(t, "", result)
		assert.Error(t, err)
	}

	mustError("A1B2C3D4E5F6G7H8I9J0")
	mustError("A0A0A0A")
	mustError("A1B 2C3D4")
	mustError("S3.Server")
	mustError("AA.11BB22CC")
	mustError("A.1.B.2.C.3")
}

func TestLogDocPrettyPrint(t *testing.T) {
	var colType, expected string

	// simple type
	colType = `string`
	expected = `string`
	assert.Equal(t, expected, prettyPrintType(logType, colName, colType, ""))

	// simple array
	colType = `array<string>`
	expected = `[string]`
	assert.Equal(t, expected, prettyPrintType(logType, colName, colType, ""))

	//  array of arrays
	colType = `array<array<string>>`
	expected = `[[string]]`
	assert.Equal(t, expected, prettyPrintType(logType, colName, colType, ""))

	//  array of maps
	colType = `array<map<string,string>>`
	expected = `[{<br>&nbsp;&nbsp;string:string<br>}]`
	assert.Equal(t, expected, prettyPrintType(logType, colName, colType, ""))

	// array of structs
	colType = `array<struct<foo:string,bar:string>>`
	expected = `[{<br>&nbsp;&nbsp;"foo":string,<br>&nbsp;&nbsp;"bar":string<br>}]`
	assert.Equal(t, expected, prettyPrintType(logType, colName, colType, ""))

	// simple map
	colType = `map<string,string>`
	expected = `{<br>&nbsp;&nbsp;string:string<br>}`
	assert.Equal(t, expected, prettyPrintType(logType, colName, colType, ""))

	// map of maps
	colType = `map<string,map<string,string>>`
	expected = `{<br>&nbsp;&nbsp;string:{<br>&nbsp;&nbsp;&nbsp;&nbsp;string:string<br>}<br>}` // nolint:lll
	assert.Equal(t, expected, prettyPrintType(logType, colName, colType, ""))

	// simple struct
	colType = `struct<foo:string,bar:string>`
	expected = `{<br>&nbsp;&nbsp;"foo":string,<br>&nbsp;&nbsp;"bar":string<br>}`
	assert.Equal(t, expected, prettyPrintType(logType, colName, colType, ""))

	// struct of array and map
	colType = `struct<foo:array<string>,bar:map<string,string>>`
	expected = `{<br>&nbsp;&nbsp;"foo":[string],<br>&nbsp;&nbsp;"bar":{<br>&nbsp;&nbsp;&nbsp;&nbsp;string:string<br>}<br>}` // nolint:lll
	assert.Equal(t, expected, prettyPrintType(logType, colName, colType, ""))

	// struct of struct
	colType = `struct<foo:struct<bar:string>>`
	expected = `{<br>&nbsp;&nbsp;"foo":{<br>&nbsp;&nbsp;&nbsp;&nbsp;"bar":string<br>}<br>}`
	assert.Equal(t, expected, prettyPrintType(logType, colName, colType, ""))

	// struct of struct of struct
	colType = `struct<foo:struct<bar:struct<zot:string>>>`
	expected = `{<br>&nbsp;&nbsp;"foo":{<br>&nbsp;&nbsp;&nbsp;&nbsp;"bar":{<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"zot":string<br>}<br>}<br>}` // nolint:lll
	assert.Equal(t, expected, prettyPrintType(logType, colName, colType, ""))
}

func TestLogDocPrettyPrintFail(t *testing.T) {
	var colType string

	// array fail
	colType = `array<>`
	assert.PanicsWithValue(t, "could not parse array type `array<>` for someColumn in SomeParserType.SomeParser",
		func() { prettyPrintType(logType, colName, colType, "") })

	// array fail
	colType = `array<foo,bar,zot>`
	assert.PanicsWithValue(t, "could not parse array type `array<foo,bar,zot>` for someColumn in SomeParserType.SomeParser",
		func() { prettyPrintType(logType, colName, colType, "") })

	// map fail
	colType = `map<>`
	assert.PanicsWithValue(t, "could not parse map type `map<>` for someColumn in SomeParserType.SomeParser",
		func() { prettyPrintType(logType, colName, colType, "") })

	// map fail
	colType = `map<foo,bar,zot>`
	assert.PanicsWithValue(t, "could not parse map type `map<foo,bar,zot>` for someColumn in SomeParserType.SomeParser",
		func() { prettyPrintType(logType, colName, colType, "") })

	// struct fail
	colType = `struct<>`
	assert.PanicsWithValue(t, "could not parse struct type `struct<>` for someColumn in SomeParserType.SomeParser",
		func() { prettyPrintType(logType, colName, colType, "") })

	// struct field fail
	colType = `struct<foo,bar>`
	assert.PanicsWithValue(t, "could not parse struct field `foo` of `struct<foo,bar>` for someColumn in SomeParserType.SomeParser",
		func() { prettyPrintType(logType, colName, colType, "") })
}
