package pantherlog

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
	"fmt"
	"reflect"
	"strconv"
	"unsafe"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

// Enum maps numbers to labels
type Enum map[int64]string

// Inverse creates a lookup finding an enum value by label
func (enum Enum) Inverse() map[string]int64 {
	lookup := make(map[string]int64, len(enum))
	for n, name := range enum {
		lookup[name] = n
	}
	return lookup
}

// MustRegisterEnum registers a type to use an enum decoder when decoding with jsoniter.
// It panics if an error occurred during registration
func MustRegisterEnum(typ reflect.Type, enum Enum) {
	if err := RegisterEnum(typ, enum); err != nil {
		panic(err)
	}
}

var registeredEnums = map[reflect.Type]Enum{}

// RegisterEnum registers a type to use an enum decoder when decoding with jsoniter.
// It returns an error in the following conditions:
// - The enum has no variants
// - The enum has duplicate labels for the variants
// - The typ argument is not based on `null.String`
// - A previous enum was registered for the same type
func RegisterEnum(typ reflect.Type, enum Enum) error {
	decoder, err := NewEnumDecoder(typ, enum)
	if err != nil {
		return err
	}
	if _, duplicate := registeredEnums[typ]; duplicate {
		return errors.New("duplicate enum decoder")
	}
	registeredEnums[typ] = enum
	jsoniter.RegisterTypeDecoder(typ.String(), decoder)
	jsoniter.RegisterTypeEncoder(typ.String(), null.StringEncoder())
	return nil
}

func NewEnumDecoder(typ reflect.Type, enum Enum) (jsoniter.ValDecoder, error) {
	if typ == nil {
		return nil, errors.New("nil type")
	}
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if !typ.ConvertibleTo(reflect.TypeOf(null.String{})) {
		return nil, errors.New("type no convertible to null.String")
	}
	if len(enum) == 0 {
		return nil, errors.New(`empty enum`)
	}
	lookup := enum.Inverse()
	if len(lookup) != len(enum) {
		return nil, errors.New(`enum contains duplicate labels`)
	}
	return &enumDecoder{
		enum:     enum,
		lookup:   lookup,
		typeName: typ.String(),
	}, nil
}

type enumDecoder struct {
	enum     Enum
	typeName string
	lookup   map[string]int64
}

func (d *enumDecoder) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	const opName = `ReadEnum`
	val := (*null.String)(ptr)
	switch iter.WhatIsNext() {
	case jsoniter.NilValue:
		iter.ReadNil()
		*val = null.String{}
	case jsoniter.NumberValue:
		n := iter.ReadInt64()
		if iter.Error != nil {
			return
		}
		name, ok := d.enum[n]
		if !ok {
			// Unknown enum variant. Convert to string. It's not our purpose to validate
			name = strconv.FormatInt(n, 10)
		}
		*val = null.FromString(name)
	case jsoniter.StringValue:
		name := iter.ReadStringAsSlice()
		if len(name) == 0 {
			// An empty string value has no other meaningful use than null
			*val = null.String{}
			return
		}
		// This map lookup does not force allocation of string
		n, ok := d.lookup[string(name)]
		if ok {
			// We lookup the name to avoid allocations
			*val = null.FromString(d.enum[n])
			return
		}
		str := string(name)
		// Try to parse the string as int to see if it's a numeric value encoded as string
		n, err := strconv.ParseInt(str, 10, 64)
		if err == nil {
			if label, ok := d.enum[n]; ok {
				*val = null.FromString(label)
				return
			}
		}
		*val = null.FromString(str)
	default:
		iter.Skip()
		iter.ReportError(opName, fmt.Sprintf(`invalid %q enum JSON value`, d.typeName))
	}
}
