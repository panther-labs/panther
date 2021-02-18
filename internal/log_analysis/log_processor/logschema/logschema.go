package logschema

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
	"encoding/json"
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/preprocessors"
	"github.com/panther-labs/panther/pkg/stringset"

	// Force dependency on go-bindata to avoid fetching during mage gen
	_ "github.com/go-bindata/go-bindata"
	"github.com/xeipuuv/gojsonschema"
)

type ValueType string

const (
	TypeObject    ValueType = "object"
	TypeArray     ValueType = "array"
	TypeTimestamp ValueType = "timestamp"
	TypeRef       ValueType = "ref"
	TypeString    ValueType = "string"
	TypeBoolean   ValueType = "boolean"
	TypeInt       ValueType = "int"
	TypeSmallInt  ValueType = "smallint"
	TypeBigInt    ValueType = "bigint"
	TypeFloat     ValueType = "float"
	TypeJSON      ValueType = "json"
)

func (t ValueType) IsComposite() bool {
	switch t {
	case TypeObject, TypeArray, TypeJSON:
		return true
	default:
		return false
	}
}

type Schema struct {
	Schema       string                  `json:"schema,omitempty" yaml:"schema,omitempty"`
	Parser       *Parser                 `json:"parser,omitempty" yaml:"parser,omitempty"`
	Description  string                  `json:"description,omitempty" yaml:"description,omitempty"`
	ReferenceURL string                  `json:"referenceURL,omitempty" yaml:"referenceURL,omitempty"`
	Version      int                     `json:"version" yaml:"version"`
	Definitions  map[string]*ValueSchema `json:"definitions,omitempty" yaml:"definitions,omitempty"`
	Fields       []FieldSchema           `json:"fields" yaml:"fields"`
}

func (s *Schema) Clone() *Schema {
	if s == nil {
		return nil
	}
	data, err := jsoniter.Marshal(s)
	if err != nil {
		// this should never happen
		panic("failed to serialize Schema to JSON: " + err.Error())
	}
	out := Schema{}
	if err := jsoniter.Unmarshal(data, &out); err != nil {
		// this should never happen
		panic("failed to deserialize Schema from JSON: " + err.Error())
	}
	return &out
}

type Parser struct {
	CSV       *preprocessors.CSVMatchConfig  `json:"csv,omitempty" yaml:"csv,omitempty"`
	FastMatch *preprocessors.FastMatchConfig `json:"fastmatch,omitempty" yaml:"fastmatch,omitempty"`
	Regex     *preprocessors.RegexConfig     `json:"regex,omitempty" yaml:"regex,omitempty"`
	Native    *NativeParser                  `json:"native,omitempty" taml:"native,omitempty"`
}

type NativeParser struct {
	Name string `json:"name" yaml:"name"`
}

type ValueSchema struct {
	Type        ValueType     `json:"type" yaml:"type"`
	Fields      []FieldSchema `json:"fields,omitempty" yaml:"fields,omitempty"`
	Element     *ValueSchema  `json:"element,omitempty" yaml:"element,omitempty"`
	Target      string        `json:"target,omitempty" yaml:"target,omitempty"`
	Indicators  []string      `json:"indicators,omitempty" yaml:"indicators,omitempty"`
	TimeFormat  string        `json:"timeFormat,omitempty" yaml:"timeFormat,omitempty"`
	IsEventTime bool          `json:"isEventTime,omitempty" yaml:"isEventTime,omitempty"`
	Validate    *Validation   `json:"validate,omitempty" yaml:"validate,omitempty"`
}

type Validation struct {
	Allow []string `json:"allow,omitempty" yaml:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty" yaml:"deny,omitempty"`
}

func (v *ValueSchema) Clone() *ValueSchema {
	if v == nil {
		return nil
	}
	switch v.Type {
	case TypeObject:
		var fields []FieldSchema
		for _, f := range v.Fields {
			cp := f.ValueSchema.Clone()
			f.ValueSchema = *cp
			fields = append(fields, f)
		}
		return &ValueSchema{
			Type:   TypeObject,
			Fields: fields,
		}
	case TypeArray:
		return &ValueSchema{
			Type:    TypeArray,
			Element: v.Element.Clone(),
		}
	case TypeTimestamp:
		return &ValueSchema{
			Type:        TypeTimestamp,
			TimeFormat:  v.TimeFormat,
			IsEventTime: v.IsEventTime,
		}
	case TypeString:
		return &ValueSchema{
			Type:       TypeString,
			Indicators: stringset.New(v.Indicators...),
		}
	case TypeRef:
		return &ValueSchema{
			Type:   TypeRef,
			Target: v.Target,
		}
	case TypeBigInt, TypeInt, TypeSmallInt, TypeFloat, TypeJSON, TypeBoolean:
		return &ValueSchema{Type: v.Type}
	default:
		return nil
	}
}

type FieldSchema struct {
	Name        string `json:"name" yaml:"name"`
	Required    bool   `json:"required,omitempty" yaml:"required,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	ValueSchema `yaml:",inline"`
}

// ValidateSchema validates the schema using the JSON schema in schema.json
func ValidateSchema(s *Schema) error {
	source, err := json.Marshal(s)
	if err != nil {
		return err
	}
	docLoader := gojsonschema.NewBytesLoader(source)
	result, err := loadJSONSchema().Validate(docLoader)
	if err != nil {
		return err
	}
	if result.Valid() {
		return nil
	}
	return errors.WithStack(&validationError{
		problems: result.Errors(),
	})
}

// loadJSONSchema loads schema.JSON using an Asset generated with go-bindata
//go:generate go run github.com/go-bindata/go-bindata/go-bindata -pkg logschema -nometadata ./schema.json
// We also copy the schema file over to web/public so it is usable by FE code
//go:generate cp ./schema.json ../../../../web/public/schemas/customlogs_v0_schema.json
var loadJSONSchema = func() *gojsonschema.Schema {
	data, err := Asset("schema.json")
	if err != nil {
		panic("failed to load JSON schema: " + err.Error())
	}
	loader := gojsonschema.NewBytesLoader(data)
	s, err := gojsonschema.NewSchema(loader)
	if err != nil {
		panic("failed to load JSON schema: " + err.Error())
	}
	return s
}

type validationError struct {
	problems []gojsonschema.ResultError
}

func (v *validationError) ValidationErrors() []gojsonschema.ResultError {
	return v.problems
}

func (v *validationError) Error() string {
	return fmt.Sprintf("validation failed with %d problems", len(v.problems))
}

func ValidationErrors(err error) (result []gojsonschema.ResultError) {
	e := &validationError{}
	if errors.As(err, &e) {
		return e.ValidationErrors()
	}
	return nil
}
