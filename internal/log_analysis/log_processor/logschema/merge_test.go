package logschema

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

// nolint:lll
func TestMerge(t *testing.T) {
	type V = ValueSchema
	type testCase struct {
		Name   string
		A, B   *ValueSchema
		Expect *ValueSchema
	}
	for _, tc := range []testCase{
		{"JSON,Object", &V{Type: TypeJSON}, &V{Type: TypeObject}, &V{Type: TypeJSON}},
		{"JSON,Array", &V{Type: TypeJSON}, &V{Type: TypeArray}, &V{Type: TypeJSON}},
		{"JSON,Timestamp", &V{Type: TypeJSON}, &V{Type: TypeTimestamp}, &V{Type: TypeJSON}},
		{"JSON,String", &V{Type: TypeJSON}, &V{Type: TypeString}, &V{Type: TypeJSON}},
		{"JSON,BigInt", &V{Type: TypeJSON}, &V{Type: TypeBigInt}, &V{Type: TypeJSON}},
		{"JSON,Int", &V{Type: TypeJSON}, &V{Type: TypeInt}, &V{Type: TypeJSON}},
		{"JSON,SmallInt", &V{Type: TypeJSON}, &V{Type: TypeSmallInt}, &V{Type: TypeJSON}},
		{"JSON,Float", &V{Type: TypeJSON}, &V{Type: TypeFloat}, &V{Type: TypeJSON}},
		{"JSON,Boolean", &V{Type: TypeJSON}, &V{Type: TypeBoolean}, &V{Type: TypeJSON}},

		{"Object,Array", &V{Type: TypeObject}, &V{Type: TypeArray}, &V{Type: TypeJSON}},
		{"Object,Timestamp", &V{Type: TypeObject}, &V{Type: TypeTimestamp}, &V{Type: TypeJSON}},
		{"Object,String", &V{Type: TypeObject}, &V{Type: TypeString}, &V{Type: TypeJSON}},
		{"Object,BigInt", &V{Type: TypeObject}, &V{Type: TypeBigInt}, &V{Type: TypeJSON}},
		{"Object,Int", &V{Type: TypeObject}, &V{Type: TypeInt}, &V{Type: TypeJSON}},
		{"Object,SmallInt", &V{Type: TypeObject}, &V{Type: TypeSmallInt}, &V{Type: TypeJSON}},
		{"Object,Float", &V{Type: TypeObject}, &V{Type: TypeFloat}, &V{Type: TypeJSON}},
		{"Object,Boolean", &V{Type: TypeObject}, &V{Type: TypeBoolean}, &V{Type: TypeJSON}},

		{"Array,Timestamp", &V{Type: TypeArray}, &V{Type: TypeTimestamp}, &V{Type: TypeJSON}},
		{"Array,String", &V{Type: TypeArray}, &V{Type: TypeString}, &V{Type: TypeJSON}},
		{"Array,Float", &V{Type: TypeArray}, &V{Type: TypeFloat}, &V{Type: TypeJSON}},
		{"Array,BigInt", &V{Type: TypeArray}, &V{Type: TypeBigInt}, &V{Type: TypeJSON}},
		{"Array,Int", &V{Type: TypeArray}, &V{Type: TypeInt}, &V{Type: TypeJSON}},
		{"Array,SmallInt", &V{Type: TypeArray}, &V{Type: TypeSmallInt}, &V{Type: TypeJSON}},
		{"Array,Boolean", &V{Type: TypeArray}, &V{Type: TypeBoolean}, &V{Type: TypeJSON}},

		{"UnixTimestamp,Float", &V{Type: TypeTimestamp, TimeFormat: "unix"}, &V{Type: TypeFloat}, &V{Type: TypeTimestamp, TimeFormat: "unix"}},
		{"UnixTimestampEvent,Float", &V{Type: TypeTimestamp, TimeFormat: "unix", IsEventTime: true}, &V{Type: TypeFloat}, &V{Type: TypeTimestamp, TimeFormat: "unix", IsEventTime: true}},
		{"UnixTimestampMS,Float", &V{Type: TypeTimestamp, TimeFormat: "unix_ms"}, &V{Type: TypeFloat}, &V{Type: TypeString}},
		{"UnixTimestampMSEvent,Float", &V{Type: TypeTimestamp, TimeFormat: "unix_ms", IsEventTime: true}, &V{Type: TypeFloat}, &V{Type: TypeString}},
		{"UnixTimestampUS,Float", &V{Type: TypeTimestamp, TimeFormat: "unix_us"}, &V{Type: TypeFloat}, &V{Type: TypeString}},
		{"UnixTimestampUSEvent,Float", &V{Type: TypeTimestamp, TimeFormat: "unix_us", IsEventTime: true}, &V{Type: TypeFloat}, &V{Type: TypeString}},
		{"UnixTimestampNS,Float", &V{Type: TypeTimestamp, TimeFormat: "unix_ns"}, &V{Type: TypeFloat}, &V{Type: TypeString}},
		{"UnixTimestampNSEvent,Float", &V{Type: TypeTimestamp, TimeFormat: "unix_ns", IsEventTime: true}, &V{Type: TypeFloat}, &V{Type: TypeString}},

		{"UnixTimestampEvent,BigInt", &V{Type: TypeTimestamp, TimeFormat: "unix", IsEventTime: true}, &V{Type: TypeBigInt}, &V{Type: TypeTimestamp, TimeFormat: "unix", IsEventTime: true}},
		{"UnixTimestampMS,BigInt", &V{Type: TypeTimestamp, TimeFormat: "unix_ms"}, &V{Type: TypeBigInt}, &V{Type: TypeTimestamp, TimeFormat: "unix_ms"}},
		{"UnixTimestampMSEvent,BigInt", &V{Type: TypeTimestamp, TimeFormat: "unix_ms", IsEventTime: true}, &V{Type: TypeBigInt}, &V{Type: TypeTimestamp, TimeFormat: "unix_ms", IsEventTime: true}},
		{"UnixTimestampUS,BigInt", &V{Type: TypeTimestamp, TimeFormat: "unix_us"}, &V{Type: TypeBigInt}, &V{Type: TypeTimestamp, TimeFormat: "unix_us"}},
		{"UnixTimestampUSEvent,BigInt", &V{Type: TypeTimestamp, TimeFormat: "unix_us", IsEventTime: true}, &V{Type: TypeBigInt}, &V{Type: TypeTimestamp, TimeFormat: "unix_us", IsEventTime: true}},
		{"UnixTimestampNS,BigInt", &V{Type: TypeTimestamp, TimeFormat: "unix_ns"}, &V{Type: TypeBigInt}, &V{Type: TypeTimestamp, TimeFormat: "unix_ns"}},
		{"UnixTimestampNSEvent,BigInt", &V{Type: TypeTimestamp, TimeFormat: "unix_ns", IsEventTime: true}, &V{Type: TypeBigInt}, &V{Type: TypeTimestamp, TimeFormat: "unix_ns", IsEventTime: true}},

		{"Timestamp,String", &V{Type: TypeTimestamp}, &V{Type: TypeFloat}, &V{Type: TypeString}},
		{"Timestamp,Float", &V{Type: TypeTimestamp}, &V{Type: TypeFloat}, &V{Type: TypeString}},
		{"Timestamp,BigInt", &V{Type: TypeTimestamp}, &V{Type: TypeBigInt}, &V{Type: TypeString}},
		{"Timestamp,Int", &V{Type: TypeTimestamp}, &V{Type: TypeInt}, &V{Type: TypeString}},
		{"Timestamp,SmallInt", &V{Type: TypeTimestamp}, &V{Type: TypeSmallInt}, &V{Type: TypeString}},

		{"String,Float", &V{Type: TypeString}, &V{Type: TypeFloat}, &V{Type: TypeString}},
		{"String,BigInt", &V{Type: TypeString}, &V{Type: TypeBigInt}, &V{Type: TypeString}},
		{"String,Int", &V{Type: TypeString}, &V{Type: TypeInt}, &V{Type: TypeString}},
		{"String,SmallInt", &V{Type: TypeString}, &V{Type: TypeSmallInt}, &V{Type: TypeString}},
		{"String,Boolean", &V{Type: TypeString}, &V{Type: TypeBoolean}, &V{Type: TypeString}},

		{"Float,BigInt", &V{Type: TypeFloat}, &V{Type: TypeBigInt}, &V{Type: TypeFloat}},
		{"Float,Int", &V{Type: TypeFloat}, &V{Type: TypeInt}, &V{Type: TypeFloat}},
		{"Float,SmallInt", &V{Type: TypeFloat}, &V{Type: TypeSmallInt}, &V{Type: TypeFloat}},
		{"Float,Boolean", &V{Type: TypeFloat}, &V{Type: TypeBoolean}, &V{Type: TypeString}},

		{"BigInt,Int", &V{Type: TypeBigInt}, &V{Type: TypeInt}, &V{Type: TypeBigInt}},
		{"BigInt,SmallInt", &V{Type: TypeBigInt}, &V{Type: TypeSmallInt}, &V{Type: TypeBigInt}},
		{"BigInt,Boolean", &V{Type: TypeBigInt}, &V{Type: TypeBoolean}, &V{Type: TypeString}},

		{"Int,SmallInt", &V{Type: TypeInt}, &V{Type: TypeSmallInt}, &V{Type: TypeInt}},
		{"Int,Boolean", &V{Type: TypeInt}, &V{Type: TypeBoolean}, &V{Type: TypeString}},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			require.Equal(t, tc.Expect, Merge(tc.A, tc.B), "invalid A,B merge")
			require.Equal(t, tc.Expect, Merge(tc.B, tc.A), "invalid B,A merge")
		})
	}
}
