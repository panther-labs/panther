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
	"reflect"
	"time"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
)

var (
	typTime = reflect.TypeOf(time.Time{})
)

type eventTimeExt struct {
	jsoniter.DummyExtension
}

func (*eventTimeExt) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	for _, binding := range desc.Fields {
		field := binding.Field
		if typ := field.Type().Type1(); typ != typTime {
			continue
		}
		if tag, ok := field.Tag().Lookup(TagName); ok && tag == "event_time" {
			binding.Encoder = &eventTimeEncoder{
				ValEncoder: binding.Encoder,
			}
		}
	}
}

type eventTimeEncoder struct {
	jsoniter.ValEncoder
}

func (e *eventTimeEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return e.ValEncoder.IsEmpty(ptr)
}
func (e *eventTimeEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	e.ValEncoder.Encode(ptr, stream)
	tm := (*time.Time)(ptr)
	if tm.IsZero() {
		return
	}
	if result, ok := stream.Attachment.(*Result); ok {
		result.EventTime = *tm
	}
}
