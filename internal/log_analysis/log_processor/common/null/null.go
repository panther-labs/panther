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
	"errors"
	"reflect"

	jsoniter "github.com/json-iterator/go"
	"gopkg.in/go-playground/validator.v9"
)

var (
	typString   = reflect.TypeOf(String{})
	typNonEmpty = reflect.TypeOf(NonEmpty{})
	typInt64    = reflect.TypeOf(Int64{})
	typUint32   = reflect.TypeOf(Uint32{})
	typUint16   = reflect.TypeOf(Uint16{})
)

func init() {
	// Register jsoniter encoder/decoder for String
	jsoniter.RegisterTypeEncoder(typString.String(), StringEncoder())
	jsoniter.RegisterTypeDecoder(typString.String(), StringDecoder())
	jsoniter.RegisterTypeEncoder(typNonEmpty.String(), NonEmptyEncoder())
	jsoniter.RegisterTypeDecoder(typNonEmpty.String(), StringDecoder())
	jsoniter.RegisterTypeEncoder(typInt64.String(), &int64Codec{})
	jsoniter.RegisterTypeDecoder(typInt64.String(), &int64Codec{})
	jsoniter.RegisterTypeEncoder(typUint32.String(), &uint32Codec{})
	jsoniter.RegisterTypeDecoder(typUint32.String(), &uint32Codec{})
	jsoniter.RegisterTypeEncoder(typUint16.String(), &uint16Codec{})
	jsoniter.RegisterTypeDecoder(typUint16.String(), &uint16Codec{})
}

func MustRegisterString(types ...interface{}) {
	for _, typ := range types {
		if err := RegisterString(typ); err != nil {
			panic(err)
		}
	}
}

func RegisterString(x interface{}) error {
	if x == nil {
		return errors.New(`invalid value`)
	}
	typ := reflect.TypeOf(x)
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if !canCastUnsafe(typ, typString) {
		return errors.New(`invalid type`)
	}
	typName := typ.String()
	if typName == "" {
		return errors.New(`anonymous type`)
	}
	jsoniter.RegisterTypeEncoder(typName, StringEncoder())
	jsoniter.RegisterTypeDecoder(typName, StringDecoder())
	return nil
}

func canCastUnsafe(from, to reflect.Type) bool {
	if from.ConvertibleTo(to) {
		return true
	}
	if from.Kind() == reflect.Struct {
		field := from.Field(0)
		if field.Anonymous && field.Type.ConvertibleTo(to) {
			return true
		}
	}
	return false
}

// RegisterValidators registers custom type validators for null values
func RegisterValidators(v *validator.Validate) {
	v.RegisterCustomTypeFunc(func(v reflect.Value) interface{} {
		return v.Field(0).String()
	}, String{}, NonEmpty{})
	v.RegisterCustomTypeFunc(func(v reflect.Value) interface{} {
		return v.Field(0).Int()
	}, Int64{})
	v.RegisterCustomTypeFunc(func(v reflect.Value) interface{} {
		return uint16(v.Field(0).Uint())
	}, Uint16{}, NonEmpty{})
	v.RegisterCustomTypeFunc(func(v reflect.Value) interface{} {
		return uint32(v.Field(0).Uint())
	}, Uint32{}, NonEmpty{})
}
