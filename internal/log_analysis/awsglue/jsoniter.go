package awsglue

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
	"time"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
)

// TODO: [pantherlog] Add more mappings of invalid Athena field name characters here
// NOTE: The mapping should be easy to remember (so no ASCII code etc) and complex enough
// to avoid possible conflicts with other fields.
var fieldNameReplacer = strings.NewReplacer(
	"@", "_at_sign_",
	",", "_comma_",
	"`", "_backtick_",
	"'", "_apostrophe_",
)

func RewriteFieldName(name string) string {
	result := fieldNameReplacer.Replace(name)
	if result == name {
		return name
	}
	return strings.Trim(result, "_")
}

const TimestampLayout = `2006-01-02 15:04:05.000000000`
const TimestampLayoutJSON = `"2006-01-02 15:04:05.000000000"`

func NewTimestampEncoder() jsoniter.ValEncoder {
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
		stream.SetBuffer(tm.UTC().AppendFormat(stream.Buffer(), TimestampLayoutJSON))
	}
}
