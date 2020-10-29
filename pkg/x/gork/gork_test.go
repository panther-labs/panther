package gork

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
	"testing"

	"github.com/stretchr/testify/require"
)

// nolint:lll
func TestMatchString(t *testing.T) {
	assert := require.New(t)
	env := New()
	src := `%{DATA:remote_ip} %{DATA:identity} %{DATA:user} \[%{HTTPDATE:timestamp}\] "%{DATA:method} %{DATA:request_uri} %{DATA:protocol}" %{DATA:status} %{DATA:bytes_sent}$`
	pattern, err := env.Compile(src)
	assert.NoError(err)
	input := "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326"
	matches, err := pattern.MatchString(nil, input)
	assert.NoError(err)
	assert.Equal([]string{
		"remote_ip", "127.0.0.1",
		"identity", "-",
		"user", "frank",
		"timestamp", "10/Oct/2000:13:55:36 -0700",
		"method", "GET",
		"request_uri", "/apache_pb.gif",
		"protocol", "HTTP/1.0",
		"status", "200",
		"bytes_sent", "2326",
	}, matches)
}

func TestRecursive(t *testing.T) {
	assert := require.New(t)
	{
		env := Env{}
		patterns := `FOO %{FOO}`
		err := env.ReadPatterns(strings.NewReader(patterns))
		assert.Error(err)
		assert.Contains(err.Error(), "recursive")
	}
	{
		env := Env{}
		patterns := `
FOO %{BAR}
BAR %{FOO}`
		err := env.ReadPatterns(strings.NewReader(patterns))
		assert.Error(err)
		assert.Contains(err.Error(), "recursive")
	}
}
