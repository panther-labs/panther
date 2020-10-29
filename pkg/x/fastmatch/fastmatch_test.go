package fastmatch

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

func TestMatchString(t *testing.T) {
	type testCase struct {
		Name    string
		Input   string
		Pattern string
		Matches []string
	}
	for _, tc := range []testCase{
		{"two fields", "foo bar", "%{foo} %{bar}", []string{"foo", "foo", "bar", "bar"}},
		{"two fields prefix", "LOG: foo bar", "LOG: %{foo} %{bar}", []string{"foo", "foo", "bar", "bar"}},
		{"no match", "foo", "%{foo} %{bar}", nil},
		{"two fields empty last", "foo ", "%{foo} %{bar}", []string{"foo", "foo", "bar", ""}},
		{"two fields empty first", " bar", "%{foo} %{bar}", []string{"foo", "", "bar", "bar"}},
		{"two fields quoted first", `"\"foo\" bar" baz`, `"%{foo}" %{bar}`, []string{"foo", `"foo" bar`, "bar", "baz"}},
		{"two fields quoted last", `foo "\"bar\"baz"`, `%{foo} "%{bar}"`, []string{"foo", `foo`, "bar", `"bar"baz`}},
		{"two fields one empty", "foo bar", "%{foo} %{}", []string{"foo", "foo"}},
		{"common log",
			"127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326",
			`%{remote_ip} %{identity} %{user} [%{timestamp}] "%{method} %{request_uri} %{protocol}" %{status} %{bytes_sent}`,
			[]string{
				"remote_ip", "127.0.0.1",
				"identity", "-",
				"user", "frank",
				"timestamp", "10/Oct/2000:13:55:36 -0700",
				"method", "GET",
				"request_uri", "/apache_pb.gif",
				"protocol", "HTTP/1.0",
				"status", "200",
				"bytes_sent", "2326",
			},
		},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			assert := require.New(t)
			p, err := Compile(tc.Pattern)
			assert.NoError(err)
			match, err := p.MatchString(nil, tc.Input)
			assert.Equal(tc.Matches != nil, err == nil)
			assert.Equal(tc.Matches, match, "invalid match\nexpect: %v\nactual: %v", tc.Matches, match)
		})
	}
}

func TestPattern_match(t *testing.T) {
	// nolint:maligned
	type testCase struct {
		Name      string
		Input     string
		Delimiter string
		Quote     byte
		Tail      string
		Match     string
		WantErr   bool
	}
	for _, tc := range []testCase{
		{"simple", "foo ", " ", 0, "", "foo", false},
		{"double quote", `foo \"bar\"" `, "\" ", '"', "", `foo "bar"`, false},
		{"single quote", `foo \'bar\'' `, "' ", '\'', "", `foo 'bar'`, false},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			assert := require.New(t)
			p := Pattern{}
			match, tail, err := p.match(tc.Input, tc.Delimiter, tc.Quote)
			if tc.WantErr {
				assert.Error(err)
				assert.Empty(match)
				assert.Equal(tc.Input, tail)
				return
			}
			assert.NoError(err)
			assert.Equal(tc.Match, match)
			assert.Equal(tc.Tail, tail)
		})
	}
}
