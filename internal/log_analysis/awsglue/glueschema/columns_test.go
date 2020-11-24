package glueschema

import (
	"github.com/stretchr/testify/require"
	"testing"
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
		{"foo-bar", "foo_bar"},
		{"$foo", "dollar_sign_foo"},
	} {
		colName := ColumnName(tc.FieldName)
		assert.Equal(tc.ColumnName, colName)
	}
}
