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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestColumnName(t *testing.T) {
	type testCase struct {
		FieldName  string
		ColumnName string
	}
	assert := require.New(t)
	for _, tc := range []testCase{
		{"@foo", "at_sign_foo"},
		{"foo,bar", "foo_comma_bar"},
		{"`foo`", "backtick_foo_backtick"},
		{"'foo'", "apostrophe_foo_apostrophe"},
		{"foo.bar", "foo_bar"},
		{".foo", "_foo"},
		{"foo-bar", "foo-bar"},
		{"$foo", "dollar_sign_foo"},
		{"Μύκονοοοος", "Mykonoooos"},
		{"foo\\bar", "foo_backslash_bar"},
		{"<foo>bar", "_foo_bar"},
	} {
		colName := ColumnName(tc.FieldName)
		assert.Equal(tc.ColumnName, colName)
	}
}
