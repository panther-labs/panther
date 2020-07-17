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
	"strings"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
	"github.com/modern-go/reflect2"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/jsonutil"
)

var (
	registeredTypes = map[reflect2.Type][]ValueKind{}
	rewriteFields   = jsonutil.NewEncoderNamingStrategy(RewriteFieldName)
	omitemptyAll    = jsonutil.NewOmitempty("json")
	// JSON is a custom jsoniter config to properly remap field names for compatibility with Athena views
	jsonAPI = BuildJSON(jsoniter.Config{
		EscapeHTML: true,
		// Validate raw JSON messages to make sure queries work as expected
		ValidateJsonRawMessage: true,
		// We don't need sorted map keys
		SortMapKeys: false,
	})
)

func JSON() jsoniter.API {
	return jsonAPI
}
func MustRegisterCustomEncoder(f ValueWriterTo, kinds ...ValueKind) {
	if err := RegisterCustomEncoder(f, kinds...); err != nil {
		panic(err)
	}
}

func RegisterCustomEncoder(f ValueWriterTo, kinds ...ValueKind) error {
	if f == nil {
		return errors.New(`nil field`)
	}
	if err := checkKinds(kinds); err != nil {
		return err
	}
	val := reflect.ValueOf(f)
	typ := val.Elem().Type()
	typ = derefType(typ)
	typName := typ.String()
	if typName == "" {
		return errors.New("anonymous type")
	}
	typ2 := reflect2.Type2(typ)
	if _, duplicate := registeredTypes[typ2]; duplicate {
		return errors.New("duplicate scanner mapping")
	}
	registeredTypes[typ2] = kinds
	return nil
}

func BuildJSON(config jsoniter.Config) jsoniter.API {
	api := config.Froze()
	api.RegisterExtension(rewriteFields)
	api.RegisterExtension(omitemptyAll)
	api.RegisterExtension(&customEncodersExt{})
	return api
}

type customEncodersExt struct {
	jsoniter.DummyExtension
}

func (*customEncodersExt) DecorateEncoder(typ2 reflect2.Type, encoder jsoniter.ValEncoder) jsoniter.ValEncoder {
	if _, ok := registeredTypes[typ2]; !ok {
		return encoder
	}
	return &customEncoder{
		ValEncoder: encoder,
		typ:        typ2.Type1(),
	}
}

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
func derefType(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	return typ
}

func checkKinds(kinds []ValueKind) error {
	if len(kinds) == 0 {
		return errors.New("no value kinds")
	}
	for _, kind := range kinds {
		if kind == KindNone {
			return errors.New("zero value kind")
		}
	}
	return nil
}
