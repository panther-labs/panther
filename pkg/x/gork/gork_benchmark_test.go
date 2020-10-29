package gork_test

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

	"github.com/panther-labs/panther/pkg/x/gork"
)

//nolint:lll
func BenchmarkMatchString(b *testing.B) {
	env := gork.New()
	pattern := `%{NS:remote_ip} %{NS:identity} %{NS:user} \[%{HTTPDATE:timestamp}\] "%{NS:method} %{NS:request_uri} %{NS:protocol}" %{NS:status} %{NS:bytes_sent}`
	expr, err := env.Compile(pattern)
	if err != nil {
		b.Fatal(err)
	}
	input := "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326"
	matches := make([]string, 10)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		matches, err = expr.MatchString(matches[:0], input)
		if err != nil {
			b.Fatal(err)
		}
		if len(matches) != 18 {
			b.Error(matches)
		}
	}
}
