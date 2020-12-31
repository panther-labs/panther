package models

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

func TestS3PrefixLogtypes_LongestPrefixMatch(t *testing.T) {
	pl := S3PrefixLogtypes{
		{"prefixA/", []string{"Log.A"}},
		{"prefixA/prefixB", []string{"Log.B"}},
		{"", []string{"Log.C"}},
	}

	testcases := []struct {
		objectKey string
		expected  S3PrefixLogtypesMapping
	}{
		{"prefixA/log.json", pl[0]},
		{"prefixA/pref/log.json", pl[0]},
		{"prefixA/prefixB/log.json", pl[1]},
		{"log.json", pl[2]},
		{"logs/log.json", pl[2]},
		{"prefixB/log.json", pl[2]},
	}
	for _, tc := range testcases {
		actual, _ := pl.LongestPrefixMatch(tc.objectKey)
		require.Equal(t, tc.expected, actual, "Fail for input object key '%s'", tc.objectKey)
	}
}

func TestS3PrefixLogtypes_LongestPrefixMatch_ReturnNil(t *testing.T) {
	pl := S3PrefixLogtypes{
		{"prefixA/", []string{"Log.A"}},
		{"prefixA/prefixB", []string{"Log.B"}},
	}

	_, matched := pl.LongestPrefixMatch("logs/log.json")

	// No prefix matched
	require.False(t, matched)
}
