package logs_test

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/logs"
)

func TestGJSONExtractor(t *testing.T) {

	raw := `{"foo":{"bar":42,"baz":"1.1.1.1"}}`
	ext := logs.GJSONFieldExtractor{
		"*.baz": logs.KindIPAddress,
	}
	buffer := logs.FieldBuffer{}
	err := ext.ExtractFields(raw, &buffer)
	require.NoError(t, err)
	fields := buffer.AppendFields(nil)
	require.Equal(t, fields, []logs.Field{
		{
			Kind:  logs.KindIPAddress,
			Value: "1.1.1.1",
		},
	})
}

// type SmallStringSet = pantherlog.SmallStringSet

// func TestSmallStringSetInsert(t *testing.T) {
// 	{
// 		values := SmallStringSet{}
// 		values.Insert("foo")
// 		require.Equal(t, values.Values, []string{"foo"})
// 	}
// 	{
// 		var values SmallStringSet
// 		values.Insert("foo")
// 		require.Equal(t, values.Values, []string{"foo"})
// 	}
// 	{
// 		values := SmallStringSet{}
// 		values.Insert("")
// 		require.Equal(t, values, SmallStringSet{})
// 	}
// 	{
// 		values := SmallStringSet{Values: []string{"foo"}}
// 		values.Insert("foo")
// 		require.Equal(t, values, SmallStringSet{Values: []string{"foo"}})
// 	}
// 	{
// 		values := SmallStringSet{Values: []string{"foo", "bar"}}
// 		values.Insert("foo")
// 		require.Equal(t, values, SmallStringSet{Values: []string{"foo", "bar"}})
// 	}
// 	{
// 		values := SmallStringSet{Values: []string{"foo", "bar"}}
// 		values.Insert("baz")
// 		values.Insert("")
// 		require.Equal(t, values, SmallStringSet{Values: []string{"foo", "bar", "baz"}})
// 	}
// }

// func TestSmallStringSetMarshalJSON(t *testing.T) {
// 	type testCase struct {
// 		value   *SmallStringSet
// 		json    string
// 		wantErr bool
// 	}
// 	for _, tc := range []testCase{
// 		{&SmallStringSet{Values: []string{"foo", "bar", "baz"}}, `["bar","baz","foo"]`, false},
// 		{&SmallStringSet{Values: []string{"foo"}}, `["foo"]`, false},
// 		{&SmallStringSet{Values: []string{}}, `[]`, false},
// 		{nil, `null`, false},
// 	} {
// 		tc := tc // Avoid lint whining
// 		t.Run(tc.json, func(t *testing.T) {
// 			data, err := jsoniter.Marshal(tc.value)
// 			if (err != nil) != tc.wantErr {
// 				t.Errorf("Unexpected error %s", err)
// 			}
// 			if string(data) != tc.json {
// 				t.Errorf("Invalid JSON output %q != %q", data, tc.json)
// 			}
// 		})

// 	}
// }
// func TestSmallStringSetMarshalOmitEmpty(t *testing.T) {
// 	type A struct {
// 		Values SmallStringSet `json:"values,omitempty"`
// 	}

// 	type testCase struct {
// 		value   SmallStringSet
// 		json    string
// 		wantErr bool
// 	}
// 	for _, tc := range []testCase{
// 		{SmallStringSet{Values: []string{"foo", "bar", "baz"}}, `{"values":["bar","baz","foo"]}`, false},
// 		{SmallStringSet{Values: []string{}}, `{"values":[]}`, false},
// 		{SmallStringSet{}, `{}`, false},
// 	} {
// 		tc := tc // Avoid lint whining
// 		t.Run(tc.json, func(t *testing.T) {
// 			data, err := jsoniter.Marshal(A{tc.value})
// 			if (err != nil) != (tc.wantErr) {
// 				t.Errorf("Unexpected error %s", err)
// 			}
// 			if string(data) != tc.json {
// 				t.Errorf("Invalid JSON output %q != %q", data, tc.json)
// 			}
// 		})

// 	}
// }
