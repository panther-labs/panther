package pantherlog_test

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
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

func TestScannerGJSON(t *testing.T) {
	raw := `{"foo":{"bar":42,"baz":"1.1.1.1"}}`
	ext := pantherlog.GJSONScanner{
		"*.baz": pantherlog.IPAddressScanner(),
	}
	fields, err := ext.ScanValues(nil, raw)
	require.NoError(t, err)
	require.Equal(t, fields, []pantherlog.Value{
		{
			Kind: pantherlog.KindIPAddress,
			Data: "1.1.1.1",
		},
	})
}

func TestIPAddress(t *testing.T) {
	type testCase struct {
		Value   string
		NonZero bool
	}
	for _, tc := range []testCase{
		{"1.1.1.1", true},
		{"  1.1.1.1", true},
		{"  1.1.1.1  ", true},
		{"1.1.1.1  ", true},
		{"255.0.1.1", true},
		{"2001:0db8:0000:0000:0000:ff00:0042:8329", true},
		{"", false},
		{"-", false},
	} {
		// Avoid lint
		tc := tc
		t.Run(tc.Value, func(t *testing.T) {
			field := pantherlog.IPAddress(tc.Value)
			if field.IsZero() {
				require.False(t, tc.NonZero, `logs.IPAddress(%q) invalid field`, tc.Value)
			} else {
				require.Equal(t, field.Kind, pantherlog.KindIPAddress)
				require.NotEmpty(t, field.Data)
			}
		})
	}
}

func TestFieldSlice(t *testing.T) {
	{
		fields := pantherlog.ValueSlice{
			{Kind: pantherlog.KindMD5Hash, Data: "595f44fec1e92a71d3e9e77456ba80d1"},
			{Kind: pantherlog.KindMD5Hash, Data: "71f920fa275127a7b60fa4d4d41432a3"},
			{Kind: pantherlog.KindDomainName, Data: "example.com"},
			{Kind: pantherlog.KindMD5Hash, Data: "43c191bf6d6c3f263a8cd0efd4a058ab"},
			{Kind: pantherlog.KindIPAddress, Data: "1.1.1.1"},
		}
		sort.Sort(fields)
		require.Equal(t, pantherlog.ValueSlice{
			{Kind: pantherlog.KindIPAddress, Data: "1.1.1.1"},
			{Kind: pantherlog.KindDomainName, Data: "example.com"},
			{Kind: pantherlog.KindMD5Hash, Data: "43c191bf6d6c3f263a8cd0efd4a058ab"},
			{Kind: pantherlog.KindMD5Hash, Data: "595f44fec1e92a71d3e9e77456ba80d1"},
			{Kind: pantherlog.KindMD5Hash, Data: "71f920fa275127a7b60fa4d4d41432a3"},
		}, fields)
	}
}

func TestNonEmptyScanner(t *testing.T) {
	p := pantherlog.NonEmptyScanner(pantherlog.KindDomainName)
	{
		fields, err := p.ScanValues(nil, "foo")
		require.NoError(t, err)
		require.Equal(t, []pantherlog.Value{
			{Kind: pantherlog.KindDomainName, Data: "foo"},
		}, fields)
		fields, err = p.ScanValues(fields, "bar")
		require.NoError(t, err)
		require.Equal(t, []pantherlog.Value{
			{Kind: pantherlog.KindDomainName, Data: "foo"},
			{Kind: pantherlog.KindDomainName, Data: "bar"},
		}, fields)
		fields, err = p.ScanValues(fields, " ")
		require.NoError(t, err)
		require.Equal(t, []pantherlog.Value{
			{Kind: pantherlog.KindDomainName, Data: "foo"},
			{Kind: pantherlog.KindDomainName, Data: "bar"},
		}, fields)
	}
	{
		fields, err := p.ScanValues(nil, "")
		require.NoError(t, err)
		require.Nil(t, fields)
	}
}
func TestScannerURL_ScanValues(t *testing.T) {
	s := ScanURL()
}
