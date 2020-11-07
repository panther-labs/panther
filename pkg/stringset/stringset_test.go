package stringset

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
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConcat(t *testing.T) {
	type testCase struct {
		Args   [][]string
		Expect []string
	}
	for i, tc := range []testCase{
		{
			Args: [][]string{
				{"foo", "bar"},
				{"foo", "baz"},
			},
			Expect: []string{"foo", "bar", "baz"},
		},
		{
			Args: [][]string{
				{"foo", "bar"},
			},
			Expect: []string{"foo", "bar"},
		},
		{
			Args: [][]string{
				{"foo", "foo"},
			},
			Expect: []string{"foo"},
		},
		{
			Args: [][]string{
				{},
				nil,
			},
			Expect: []string{},
		},
		{
			Args: [][]string{
				{"foo", "bar"},
				{"foo", "baz"},
				{"bar", "baz", "qux"},
			},
			Expect: []string{"foo", "bar", "baz", "qux"},
		},
	} {
		tc := tc
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			actual := Concat(tc.Args...)
			assert.Equal(t, tc.Expect, actual)
		})
	}
}

func TestNew(t *testing.T) {
	type testCase struct {
		Args   []string
		Expect []string
	}
	for i, tc := range []testCase{
		{
			Args:   []string{"foo", "bar", "baz"},
			Expect: []string{"foo", "bar", "baz"},
		},
		{
			Args:   []string{"foo", "bar", "baz", "foo"},
			Expect: []string{"foo", "bar", "baz"},
		},
		{
			Args:   nil,
			Expect: nil,
		},
		{
			Args:   []string{},
			Expect: []string{},
		},
	} {
		tc := tc
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			actual := New(tc.Args...)
			assert.Equal(t, tc.Expect, actual)

			if len(tc.Args) > 0 {
				// Ensure the result is a new slice
				for i := range tc.Args {
					tc.Args[i] += "foo"
				}
				assert.NotEqual(t, actual, tc.Args)
			}
		})
	}
}

func TestDedup(t *testing.T) {
	type testCase struct {
		Args   []string
		Expect []string
	}
	for i, tc := range []testCase{
		{
			Args:   []string{"foo", "bar", "baz"},
			Expect: []string{"foo", "bar", "baz"},
		},
		{
			Args:   []string{"foo", "bar", "baz", "foo"},
			Expect: []string{"foo", "bar", "baz"},
		},
		{
			Args:   nil,
			Expect: nil,
		},
		{
			Args:   []string{},
			Expect: []string{},
		},
	} {
		tc := tc
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			actual := Dedup(tc.Args)
			assert.Equal(t, tc.Expect, actual)
			if len(tc.Args) > 0 {
				// Ensure the result is the same slice
				for i := range tc.Args {
					tc.Args[i] += "foo"
				}
				assert.Equal(t, actual, tc.Args[:len(actual)])
			}
		})
	}
}
