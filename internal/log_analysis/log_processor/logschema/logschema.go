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

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/preprocessors"

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

type Schema struct {
	Schema       string                  `json:"schema,omitempty" yaml:"schema,omitempty"`
	Parser       *Parser                 `json:"parser,omitempty" yaml:"parser,omitempty"`
	Description  string                  `json:"description,omitempty" yaml:"description,omitempty"`
	ReferenceURL string                  `json:"referenceURL,omitempty" yaml:"referenceURL,omitempty"`
	Version      int                     `json:"version" yaml:"version"`
	Definitions  map[string]*ValueSchema `json:"definitions,omitempty" yaml:"definitions,omitempty"`
	Fields       []FieldSchema           `json:"fields" yaml:"fields"`
}

type Parser struct {
	CSV       *preprocessors.CSVMatchConfig  `json:"csv,omitempty" yaml:"csv,omitempty"`
	FastMatch *preprocessors.FastMatchConfig `json:"fastmatch,omitempty" yaml:"fastmatch,omitempty"`
	Regex     *preprocessors.RegexConfig     `json:"regex,omitempty" yaml:"regex,omitempty"`
}

type ValueSchema struct {
	Type        ValueType     `json:"type" yaml:"type"`
	Fields      []FieldSchema `json:"fields,omitempty" yaml:"fields,omitempty"`
	Element     *ValueSchema  `json:"element,omitempty" yaml:"element,omitempty"`
	Target      string        `json:"target,omitempty" yaml:"target,omitempty"`
	Indicators  []string      `json:"indicators,omitempty" yaml:"indicators,omitempty"`
	TimeFormat  string        `json:"timeFormat,omitempty" yaml:"timeFormat,omitempty"`
	IsEventTime bool          `json:"isEventTime,omitempty" yaml:"isEventTime,omitempty"`
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
