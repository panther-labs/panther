package glueschema

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
	"strings"
	"unicode"

	anyascii "github.com/anyascii/go"
)

// Column is a table column in AWS Glue.
// We are using a separate struct from glue.Column to be able to mark the column as required
type Column struct {
	// Name is the name of the colunm
	Name string
	// Type is the glue schema type for the column.
	Type Type // this is the Glue type
	// Comment is used to set the comment in the glue column and also to set the
	// field description in generated documentation.
	Comment string
	// Required marks the column as required.
	// This information is used in documentation to mark fields as required.
	// It does not affect Glue schema in some way and this should be removed once
	// doc generation evolves to not use []glueschema.Column as input.
	Required bool
}

// ColumnName normalizes names to be used for Glue table columns
func ColumnName(name string) string {
	out := strings.Builder{}
	characters := []rune(name)
	last := len(characters) - 1
	for i, r := range characters {
		switch {
		case 'a' <= r && r <= 'z':
			out.WriteRune(r)
		case 'A' <= r && r <= 'Z': // we keep the case
			out.WriteRune(r)
		case '0' <= r && r <= '9':
			out.WriteRune(r)
		case r == '_' || r == '-': // Apparently '-' is allowed but needs to be quoted in queries.
			out.WriteRune(r)
		default:
			if s, ok := transliterateChars[r]; ok {
				// prepend '_' if not at the start of the string
				if i > 0 {
					out.WriteByte('_')
				}
				out.WriteString(s)
				// append '_' if not at the end of the string
				if i < last {
					out.WriteByte('_')
				}
				continue
			}
			if unicode.IsLetter(r) {
				// Try to handle non-ASCII letters gracefully
				if s := anyascii.TransliterateRune(r); s != "" {
					out.WriteString(s)
					continue
				}
			}
			out.WriteRune('_')
		}
	}
	return out.String()
}

// TODO: [glueschema] Add more mappings of invalid Athena field name characters here
// NOTE: The mapping should be easy to remember (so no ASCII code etc) and complex enough
// to avoid possible conflicts with other fields.
var transliterateChars = map[rune]string{
	'@':  "at_sign",
	',':  "comma",
	'`':  "backtick",
	'\'': "apostrophe",
	'$':  "dollar_sign",
	'*':  "asterisk",
	'&':  "ampersand",
	'!':  "exclamation",
	'%':  "percent",
	'+':  "plus",
	'/':  "slash",
	'\\': "backslash",
	'#':  "hash",
	'~':  "tilde",
	'=':  "eq",
}
