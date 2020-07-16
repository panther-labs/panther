// Package null provides performant nullable values for JSON serialization/deserialization
package null

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

	jsoniter "github.com/json-iterator/go"
)

func init() {
	// Register jsoniter encoder/decoder for String
	typString := reflect.TypeOf(String{})
	jsoniter.RegisterTypeEncoder(typString.String(), StringEncoder())
	jsoniter.RegisterTypeDecoder(typString.String(), StringDecoder())
	typNonEmpty := reflect.TypeOf(NonEmpty{})
	jsoniter.RegisterTypeEncoder(typNonEmpty.String(), NonEmptyEncoder())
	jsoniter.RegisterTypeDecoder(typNonEmpty.String(), StringDecoder())
	typInt64 := reflect.TypeOf(Int64{})
	jsoniter.RegisterTypeEncoder(typInt64.String(), &int64Codec{})
	jsoniter.RegisterTypeDecoder(typInt64.String(), &int64Codec{})
	typUint32 := reflect.TypeOf(Uint32{})
	jsoniter.RegisterTypeEncoder(typUint32.String(), &uint32Codec{})
	jsoniter.RegisterTypeDecoder(typUint32.String(), &uint32Codec{})
	typUint16 := reflect.TypeOf(Uint16{})
	jsoniter.RegisterTypeEncoder(typUint16.String(), &uint16Codec{})
	jsoniter.RegisterTypeDecoder(typUint16.String(), &uint16Codec{})
}
