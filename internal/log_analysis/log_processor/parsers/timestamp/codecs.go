package timestamp

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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"reflect"
	"time"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
)

// NewEncoder returns a jsoniter.ValEncoder that marshals timestamps to JSON.
// It minimizes allocations by using `time.AppendFormat`.
// The zero time value is marshaled as `null`.
// The zero time value is considered empty on `omitempty`.
func NewEncoder() jsoniter.ValEncoder {
	return &rfc3339Encoder{}
}

type rfc3339Encoder struct{}

func (*rfc3339Encoder) IsEmpty(ptr unsafe.Pointer) bool {
	tm := (*time.Time)(ptr)
	return tm.IsZero()
}

func (*rfc3339Encoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	tm := (*time.Time)(ptr)
	if tm.IsZero() {
		stream.WriteNil()
	} else {
		stream.SetBuffer(AppendJSON(stream.Buffer(), *tm))
	}
}

func init() {
	// Use efficient encoder for all timestamps
	typUnixMillis := reflect.TypeOf(UnixMillisecond{})
	jsoniter.RegisterTypeEncoder(typUnixMillis.String(), &rfc3339Encoder{})
	typUnixFloat := reflect.TypeOf(UnixFloat{})
	jsoniter.RegisterTypeEncoder(typUnixFloat.String(), &rfc3339Encoder{})
	typRFC3339 := reflect.TypeOf(RFC3339{})
	jsoniter.RegisterTypeEncoder(typRFC3339.String(), &rfc3339Encoder{})
	typANSICwithTZ := reflect.TypeOf(ANSICwithTZ{})
	jsoniter.RegisterTypeEncoder(typANSICwithTZ.String(), &rfc3339Encoder{})
	typFluentd := reflect.TypeOf(FluentdTimestamp{})
	jsoniter.RegisterTypeEncoder(typFluentd.String(), &rfc3339Encoder{})
	typSuricata := reflect.TypeOf(SuricataTimestamp{})
	jsoniter.RegisterTypeEncoder(typSuricata.String(), &rfc3339Encoder{})
}
