package jsonutil

import (
	"strings"
	"testing"

	jsoniter "github.com/json-iterator/go"
)

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

func TestStripObjectDelimiters(t *testing.T) {
	type testCase struct {
		JSON string
		Want string
	}

	for _, tc := range []testCase{
		{"{}", ""},
		{`{"foo":"bar"}`, `"foo":"bar"`},
		{`{"foo":"bar","bar":"baz"}`, `"foo":"bar","bar":"baz"`},
		{`null`, `null`},
		{`"foo"`, `"foo"`},
		{`42`, `42`},
	} {
		tc := tc
		stripped := StripObjectDelimiters([]byte(tc.JSON))
		if string(stripped) != tc.Want {
			t.Errorf("Invalid strip output %q: %q != %q", tc.JSON, stripped, tc.Want)
		}
	}
}

func TestJoinObjects(t *testing.T) {
	// nolint
	type testCase struct {
		Delimiter byte
		JSON      string
		Want      string
		WantErr   bool
	}

	// nolint:lll
	for _, tc := range []testCase{
		{'\n', "{}", "{}", false},
		{'\n', `{"foo":"bar"}`, `{"foo":"bar"}`, false},
		{'\n', `{"foo":"bar"}` + "\n" + `{"bar":"baz"}`, `{"foo":"bar","bar":"baz"}`, false},
		{'\x00', `{"foo":"bar"}` + "\x00" + `{"bar":"baz"}`, `{"foo":"bar","bar":"baz"}`, false},
		{'\n', `{"foo":"bar"}` + "\n" + `{"bar":"baz"}` + "\n" + `{"baz":"foo","answer":42}`, `{"foo":"bar","bar":"baz","baz":"foo","answer":42}`, false},
	} {
		tc := tc
		joined, err := JoinObjects(tc.Delimiter, nil, []byte(tc.JSON))
		if tc.WantErr != (err != nil) {
			t.Errorf("Invalid error %v", err)
		}
		if string(joined) != tc.Want {
			t.Errorf("Invalid strip output %q: %q != %q", tc.JSON, joined, tc.Want)
		}
	}
}

func TestJoinObjectsInplace(t *testing.T) {
	buffer := []byte(strings.Join([]string{
		`{"foo":"bar"}`,
		`{"bar":"baz"}`,
	}, "\n"))
	result, err := JoinObjects('\n', buffer[:0], buffer)
	if err != nil {
		t.Errorf("Unexpected error %s", err)
	}
	if string(result) != `{"foo":"bar","bar":"baz"}` {
		t.Errorf("Invalid join output %q", result)
	}
}

func TestConcatObjects(t *testing.T) {
	type A struct {
		Foo string `json:"foo"`
		Bar string `json:"bar"`
	}
	type B struct {
		Baz string `json:"baz"`
	}
	a := A{
		Foo: "foo",
		Bar: "bar",
	}
	b := B{
		Baz: "baz",
	}
	buf, err := ConcatObjects(jsoniter.ConfigDefault, nil, a, b)
	if err != nil {
		t.Errorf("failed to concat objects: %s", err)
	}
	if string(buf) != `{"foo":"foo","bar":"bar","baz":"baz"}` {
		t.Errorf("invalid JSON %s", buf)
	}
}
