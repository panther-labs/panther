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
	"github.com/modern-go/reflect2"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/jsonutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

var (
	// JSON is a custom jsoniter config to properly remap field names for compatibility with Athena views
	jsonAPI = BuildJSON(jsoniter.Config{
		EscapeHTML: true,
		// Validate raw JSON messages to make sure queries work as expected
		ValidateJsonRawMessage: true,
		// We don't need sorted map keys
		SortMapKeys: false,
	})
	typValueWriterTo = reflect.TypeOf((*ValueWriterTo)(nil)).Elem()
)

func JSON() jsoniter.API {
	return jsonAPI
}

func BuildJSON(config jsoniter.Config) jsoniter.API {
	api := config.Froze()
	api.RegisterExtension(jsonutil.NewEncoderNamingStrategy(awsglue.RewriteFieldName))
	tcodec.RegisterJSONEncoder(api, awsglue.TimestampLayout, time.UTC)
	api.RegisterExtension(tcodec.NewDecoderExtension())
	api.RegisterExtension(jsonutil.NewOmitempty("json"))
	api.RegisterExtension(&scanValueEncodersExt{})
	api.RegisterExtension(&customEncodersExt{})
	return api
}

type customEncodersExt struct {
	jsoniter.DummyExtension
}

func (*customEncodersExt) DecorateEncoder(typ2 reflect2.Type, encoder jsoniter.ValEncoder) jsoniter.ValEncoder {
	typ := typ2.Type1()
	isPtr := typ.Kind() == reflect.Ptr
	if isPtr {
		return encoder
	}
	typPtr := reflect.PtrTo(typ)
	if typPtr.Implements(typValueWriterTo) {
		return &customEncoder{
			ValEncoder: encoder,
			typ:        typ,
		}
	}
	return encoder
}

type customEncoder struct {
	jsoniter.ValEncoder
	typ reflect.Type
}

func (e *customEncoder) IsEmpty(ptr unsafe.Pointer) bool {
	return e.ValEncoder.IsEmpty(ptr)
}
func (e *customEncoder) Encode(ptr unsafe.Pointer, stream *jsoniter.Stream) {
	e.ValEncoder.Encode(ptr, stream)
	if stream.Error != nil {
		return
	}
	if w, ok := stream.Attachment.(ValueWriter); ok {
		val := reflect.NewAt(e.typ, ptr)
		val.Interface().(ValueWriterTo).WriteValuesTo(w)
	}
}
