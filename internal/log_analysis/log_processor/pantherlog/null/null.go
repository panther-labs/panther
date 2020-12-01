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
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue/glueschema"
)

var (
	typString   = reflect.TypeOf(String{})
	typNonEmpty = reflect.TypeOf(NonEmpty{})
	typInt64    = reflect.TypeOf(Int64{})
	typInt32    = reflect.TypeOf(Int32{})
	typInt16    = reflect.TypeOf(Int16{})
	typInt8     = reflect.TypeOf(Int8{})
	typUint64   = reflect.TypeOf(Uint64{})
	typUint32   = reflect.TypeOf(Uint32{})
	typUint16   = reflect.TypeOf(Uint16{})
	typUint8    = reflect.TypeOf(Uint8{})
	typFloat64  = reflect.TypeOf(Float64{})
	typFloat32  = reflect.TypeOf(Float32{})
	typBoolean  = reflect.TypeOf(Bool{})
)

func init() {
	// Register jsoniter encoder/decoder for String
	jsoniter.RegisterTypeEncoder(typString.String(), StringEncoder())
	jsoniter.RegisterTypeDecoder(typString.String(), StringDecoder())
	jsoniter.RegisterTypeEncoder(typNonEmpty.String(), NonEmptyEncoder())
	jsoniter.RegisterTypeDecoder(typNonEmpty.String(), StringDecoder())

	jsoniter.RegisterTypeEncoder(typInt64.String(), &int64Codec{})
	jsoniter.RegisterTypeDecoder(typInt64.String(), &int64Codec{})
	jsoniter.RegisterTypeEncoder(typInt32.String(), &int32Codec{})
	jsoniter.RegisterTypeDecoder(typInt32.String(), &int32Codec{})
	jsoniter.RegisterTypeEncoder(typInt16.String(), &int16Codec{})
	jsoniter.RegisterTypeDecoder(typInt16.String(), &int16Codec{})
	jsoniter.RegisterTypeEncoder(typInt8.String(), &int8Codec{})
	jsoniter.RegisterTypeDecoder(typInt8.String(), &int8Codec{})

	jsoniter.RegisterTypeEncoder(typUint64.String(), &uint64Codec{})
	jsoniter.RegisterTypeDecoder(typUint64.String(), &uint64Codec{})
	jsoniter.RegisterTypeEncoder(typUint32.String(), &uint32Codec{})
	jsoniter.RegisterTypeDecoder(typUint32.String(), &uint32Codec{})
	jsoniter.RegisterTypeEncoder(typUint16.String(), &uint16Codec{})
	jsoniter.RegisterTypeDecoder(typUint16.String(), &uint16Codec{})
	jsoniter.RegisterTypeEncoder(typUint8.String(), &uint8Codec{})
	jsoniter.RegisterTypeDecoder(typUint8.String(), &uint8Codec{})

	jsoniter.RegisterTypeEncoder(typFloat64.String(), &float64Codec{})
	jsoniter.RegisterTypeDecoder(typFloat64.String(), &float64Codec{})
	jsoniter.RegisterTypeEncoder(typFloat32.String(), &float32Codec{})
	jsoniter.RegisterTypeDecoder(typFloat32.String(), &float32Codec{})

	jsoniter.RegisterTypeEncoder(typBoolean.String(), &boolCodec{})
	jsoniter.RegisterTypeDecoder(typBoolean.String(), &boolCodec{})

	glueschema.MustRegisterMapping(typFloat64, glueschema.TypeDouble)
	glueschema.MustRegisterMapping(typFloat32, glueschema.TypeFloat)
	glueschema.MustRegisterMapping(typInt64, glueschema.TypeBigInt)
	glueschema.MustRegisterMapping(typInt32, glueschema.TypeInt)
	glueschema.MustRegisterMapping(typInt16, glueschema.TypeSmallInt)
	glueschema.MustRegisterMapping(typInt8, glueschema.TypeTinyInt)
	glueschema.MustRegisterMapping(typUint64, glueschema.TypeBigInt)
	glueschema.MustRegisterMapping(typUint32, glueschema.TypeBigInt)
	glueschema.MustRegisterMapping(typUint16, glueschema.TypeInt)
	glueschema.MustRegisterMapping(typUint8, glueschema.TypeSmallInt)
	glueschema.MustRegisterMapping(typString, glueschema.TypeString)
	glueschema.MustRegisterMapping(typNonEmpty, glueschema.TypeString)
	glueschema.MustRegisterMapping(typBoolean, glueschema.TypeBool)
}

// RegisterValidators registers custom type validators for null values
func RegisterValidators(validate *validator.Validate) {
	validate.RegisterCustomTypeFunc(ValidateNullType, String{}, NonEmpty{},
		Float64{}, Float32{},
		Int64{}, Int32{}, Int16{}, Int8{},
		Uint64{}, Uint32{}, Uint16{}, Uint8{},
	)
}

func ValidateNullType(val reflect.Value) interface{} {
	if val.Field(1).Bool() {
		// We want a pointer value to catch only `null` and missing fields with `required`
		// Otherwise numbers and booleans would fail if set to 0 or false and empty strings would be invalid.
		fieldValue := val.Field(0)
		ptrValue := reflect.New(fieldValue.Type())
		ptrValue.Elem().Set(fieldValue)
		return ptrValue.Interface()
	}
	return nil
}

func unquoteJSON(data []byte) []byte {
	if len(data) > 1 && data[0] == '"' {
		data = data[1:]
		if n := len(data) - 1; 0 <= n && n < len(data) && data[n] == '"' {
			return data[:n]
		}
	}
	return data
}
