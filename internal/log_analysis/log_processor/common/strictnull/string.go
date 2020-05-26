package strictnull

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
	"reflect"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common/null"
)

// String is a nullable string value that retains empty string in the input
// It's useful to handle string JSON values that could be `null` in the incoming log JSON.
// It's `omitempty` behavior when used with `jsoniter` is to only omit `null` in the output
type String struct {
	null.String
}

// FromString creates a non-null String.
// It is inlined by the compiler.
func FromString(s string) String {
	return String{
		String: null.FromString(s),
	}
}

// stringCodec is a jsoniter encoder/decoder for String values
type stringCodec struct{}

// Encode implements jsoniter.ValEncoder interface
func (*stringCodec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	if str := (*String)(ptr); str.Exists {
		stream.WriteString(str.Value)
	} else {
		stream.WriteNil()
	}
}

// IsEmpty implements jsoniter.ValEncoder interface
// WARNING: This considers *both* `null` and `""` values as empty and omits them
func (*stringCodec) IsEmpty(ptr unsafe.Pointer) bool {
	// A String is non empty only when it's non null and it's Value is not ""
	if str := (*String)(ptr); str.Exists {
		return false
	}
	return true
}

func init() {
	// Register jsoniter encoder/decoder for String
	typ := reflect.TypeOf((*String)(nil)).Elem()
	jsoniter.RegisterTypeEncoder(typ.String(), &stringCodec{})
}
