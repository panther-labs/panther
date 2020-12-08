package logstream

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
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLineStream(t *testing.T) {
	type testCase struct {
		Name    string
		Input   []byte
		Expect  []string
		WantErr bool
	}
	for _, tc := range []testCase{
		{
			Name:    "Binary data",
			Input:   []byte{0, 0, 0, 0, 0, 0, 0, 0},
			WantErr: true,
		},
		{
			Name:    "Empty lines followed by binary",
			Input:   []byte{'\n', '\n', 0xF0, 0x10, 0x32},
			WantErr: true,
		},
		{
			Name:  "Single line",
			Input: []byte("foo bar baz"),
			Expect: []string{
				"foo bar baz",
			},
			WantErr: false,
		},
		{
			Name: "Two lines",
			Input: []byte(`foo bar baz
foo bar baz`),
			Expect: []string{
				"foo bar baz",
				"foo bar baz",
			},
			WantErr: false,
		},
		{
			Name:    "Long Line",
			Input:   []byte(longLine),
			Expect:  []string{longLine},
			WantErr: false,
		},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			r := bytes.NewReader(tc.Input)
			s := NewLineStream(r, 16)
			var result []string
			for {
				entry := s.Next()
				if entry == nil {
					break
				}
				result = append(result, string(entry))
			}
			err := s.Err()
			if tc.WantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.Expect, result)
		})
	}
}

const longLine = "foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz " +
	"foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz " +
	"foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz " +
	"foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz " +
	"foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz " +
	"foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz foo bar baz "

func TestIsValidUTF8(t *testing.T) {
	p := []byte{'a', 'b', 'c', 0xAF, 0x10, 0x32}
	require.False(t, isValidUTF8(p, true))
}
