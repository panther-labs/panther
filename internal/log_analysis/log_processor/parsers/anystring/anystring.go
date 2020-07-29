package anystring

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
	"sort"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
)

type Set struct { // needed to declare as struct (rather than map) for CF generation
	Values []string
}

func From(values ...string) *Set {
	set := Set{
		Values: make([]string, 0, len(values)),
	}
	for _, v := range values {
		set.Add(v)
	}
	return &set
}

func (any *Set) Add(value string) {
	if value == "" {
		return
	}
	for _, v := range any.Values {
		if v == value {
			return
		}
	}
	any.Values = append(any.Values, value)
}
func New() *Set {
	return &Set{}
}

func (any Set) MarshalJSON() ([]byte, error) {
	sort.Strings(any.Values)
	return jsoniter.Marshal(any.Values)
}

func (any *Set) UnmarshalJSON(jsonBytes []byte) error {
	return jsoniter.Unmarshal(jsonBytes, &any.Values)
}

func Append(any *Set, values ...string) {
	// add new if not present
	for _, v := range values {
		any.Add(v)
	}
}

type setCodec struct{}

func (*setCodec) IsEmpty(ptr unsafe.Pointer) bool {
	set := (*Set)(ptr)
	return len(set.Values) == 0
}
func (*setCodec) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	switch any := (*Set)(ptr); len(any.Values) {
	case 0:
		stream.WriteArrayStart()
		stream.WriteArrayEnd()
	case 1:
		v := any.Values[0]
		stream.WriteArrayStart()
		stream.WriteString(v)
		stream.WriteArrayEnd()
	default:
		sort.Strings(any.Values)
		stream.WriteVal(any.Values)
	}
}

func (*setCodec) Decode(ptr unsafe.Pointer, iter *jsoniter.Iterator) {
	any := (*Set)(ptr)
	iter.ReadVal(&any.Values)
}

func init() {
	typ := reflect.TypeOf(Set{})
	jsoniter.RegisterTypeEncoder(typ.String(), &setCodec{})
	jsoniter.RegisterTypeDecoder(typ.String(), &setCodec{})
}
