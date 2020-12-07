package customlogs

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
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

type InferOpts struct {
	File *string
}

var inferJsoniter = jsoniter.Config{
	UseNumber: true,
}.Froze()

// Infers a schema given a sample of logs
func Infer(logger *zap.SugaredLogger, opts *InferOpts) {
	if *opts.File == "" {
		flag.Usage()
		logger.Fatal("no schema file provided")
	}

	schema, err := inferFromFile(logger, *opts.File)
	if err != nil {
		logger.Fatal("failed to generate schema", zap.Error(err))
	}

	// In order to validate that the schema generated is correct,
	// run the parser against the logs, fail in case of error
	if err = validateSchema(schema, *opts.File); err != nil {
		logger.Fatal("failed while testing schema with file", zap.Error(err))
	}

	marshalled, err := yaml.Marshal(schema)
	if err != nil {
		logger.Fatal("failed to marshal schema", zap.Error(err))
	}
	fmt.Println(string(marshalled))
}

func inferFromFile(logger *zap.SugaredLogger, file string) (logschema.Schema, error) {
	schema := logschema.Schema{
		Version: 0,
	}
	fd, err := os.Open(file)
	if err != nil {
		return schema, errors.Wrap(err, "failed to read input file")
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var data map[string]interface{}
		if err = inferJsoniter.Unmarshal(line, &data); err != nil {
			return schema, errors.Wrapf(err, "failed to parse line [%d] as JSON", lineNum)
		}
		// inferring the log schema of that single line
		lineFields := inferFields(data)
		// merging the schema of this line with the schema that we have generated from all lines until now
		schema.Fields, err = mergeFields(schema.Fields, lineFields)
		if err != nil {
			return schema, errors.Wrapf(err, "failed while inferring schema from line [%d]", lineNum)
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Fatal("failed to read input file", zap.Error(err))
	}

	return schema, nil
}

// Infers the schema from a single JSON event
func inferFields(event map[string]interface{}) []logschema.FieldSchema {
	var out []logschema.FieldSchema
	for key, value := range event {
		valueSchema, ok := inferValueSchema(value)
		if !ok {
			// If we couldn't infer the schema of the value because e.g. it didn't have enough information (e.g. it is `null`)
			// don't add it
			continue
		}

		field := logschema.FieldSchema{
			Name:        key,
			Description: "The " + key,
			Required:    true,
			ValueSchema: *valueSchema,
		}
		out = append(out, field)
	}
	// sorts the fields by name. Useful so that re-runs of the same tool will generate the same schema
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// Try to infer the schema from a single value
// Returs false if we were unable to infer it
func inferValueSchema(value interface{}) (*logschema.ValueSchema, bool) {
	typ, ok := inferValueType(value)
	if !ok {
		return nil, false
	}
	switch typ {
	case logschema.TypeArray:
		array := value.([]interface{})
		// If the array has no elements, don't try to infer their type
		if len(array) == 0 {
			return nil, false
		}
		// We are trying to infer the schema of the array only by looking at the first element
		valueSchema, ok := inferValueSchema(array[0])
		if !ok {
			return nil, false
		}
		return &logschema.ValueSchema{
			Type:    typ,
			Element: valueSchema,
		}, true
	case logschema.TypeObject:
		object := value.(map[string]interface{})
		// If the object has no fields, don't try to infer its type.
		// Just skip it.
		if len(object) == 0 {
			return nil, false
		}
		return &logschema.ValueSchema{
			Type:   typ,
			Fields: inferFields(object),
		}, true
	case logschema.TypeString:
		str := value.(string)
		return guessStringValue(str), true
	default:
		return &logschema.ValueSchema{
			Type: typ,
		}, true
	}
}

func inferValueType(value interface{}) (logschema.ValueType, bool) {
	switch value.(type) {
	case bool:
		return logschema.TypeBoolean, true
	case string:
		return logschema.TypeString, true
	case json.Number:
		value := value.(json.Number)
		if _, err := value.Int64(); err != nil {
			return logschema.TypeFloat, true
		}
		return logschema.TypeBigInt, true
	case map[string]interface{}:
		return logschema.TypeObject, true
	case []interface{}:
		return logschema.TypeArray, true
	case nil:
		return logschema.TypeJSON, false
	default:
		panic("This shouldn't happen")
	}
}

// Many of the logs may have numbers, booleans in strings
func guessStringValue(value string) *logschema.ValueSchema {
	if len(value) == 0 {
		return &logschema.ValueSchema{
			Type: logschema.TypeString,
		}
	}
	// If we could parse it as integer,
	// return it as TypeBigInt
	if err := (&pantherlog.Int64{}).UnmarshalJSON([]byte(value)); err == nil {
		return &logschema.ValueSchema{
			Type: logschema.TypeBigInt,
		}

	}

	// If we could parse it as flat,
	// return it as TypeFloat
	if err := (&pantherlog.Float64{}).UnmarshalJSON([]byte(value)); err == nil {
		return &logschema.ValueSchema{
			Type: logschema.TypeFloat,
		}
	}

	// If we could parse it as boolean,
	// return it as boolean
	if err := (&pantherlog.Bool{}).UnmarshalJSON([]byte(value)); err == nil {
		return &logschema.ValueSchema{
			Type: logschema.TypeBoolean,
		}
	}

	if _, err := time.Parse(time.RFC3339, value); err == nil {
		return &logschema.ValueSchema{
			Type:       logschema.TypeTimestamp,
			TimeFormat: "rfc3339",
		}
	}

	return &logschema.ValueSchema{
		Type: logschema.TypeString,
	}
}

func mergeFields(left, right []logschema.FieldSchema) ([]logschema.FieldSchema, error) {
	if len(right) == 0 {
		return left, nil
	}
	if len(left) == 0 {
		return right, nil
	}

	leftMap := make(map[string]logschema.FieldSchema)
	for _, schema := range left {
		if _, ok := leftMap[schema.Name]; ok {
			return nil, errors.New("Found duplicate key " + schema.Name)
		}
		leftMap[schema.Name] = schema
	}

	rightMap := make(map[string]logschema.FieldSchema)
	for _, schema := range right {
		if _, ok := rightMap[schema.Name]; ok {
			return nil, errors.New("Found duplicate key " + schema.Name)
		}
		rightMap[schema.Name] = schema
	}

	for key, leftValue := range leftMap {
		rightValue, ok := rightMap[key]
		if !ok {
			// If the field didn't exist in the right schema
			// nothing else to do
			// Just mark it as optional
			leftMap[key] = setOptional(leftValue)
			continue
		}

		merged, err := mergeFieldSchema(&leftValue, &rightValue)
		if err != nil {
			return nil, errors.Wrapf(err, "failed while processing [%s]", key)
		}
		leftMap[key] = *merged
		// After we have processed this field from the rightMap, delete it
		delete(rightMap, key)
	}

	// We have already deleted from the rightMap all the fields that were also present in the leftMap
	// Add the remaining ones, and mark them as optional.
	for key, value := range rightMap {
		leftMap[key] = setOptional(value)
	}

	var out []logschema.FieldSchema
	for _, value := range leftMap {
		out = append(out, value)
	}
	// sorts the fields by name
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func setOptional(schema logschema.FieldSchema) logschema.FieldSchema {
	schema.Required = false
	if schema.Type == logschema.TypeObject {
		for i := range schema.Fields {
			schema.Fields[i].Required = false
		}
	}
	return schema
}

func mergeFieldSchema(left, right *logschema.FieldSchema) (*logschema.FieldSchema, error) {
	// If the fields are of different type,
	// try to see if it is possible be merge the types
	if left.Type != right.Type {
		newType, ok := mergeType(left.Type, right.Type)
		if !ok {
			return nil, errors.Errorf("can't assign %s to %s", string(left.Type), string(right.Type))
		}
		left.Type = newType
		return left, nil
	}

	switch left.Type {
	case logschema.TypeObject:
		merged, err := mergeFields(left.Fields, right.Fields)
		if err != nil {
			return nil, errors.Wrapf(err, "failure while processing field [%s]", left.Name)
		}
		left.Fields = merged
	case logschema.TypeArray:
		merged, err := mergeArrayElementSchema(left.Element, right.Element)
		if err != nil {
			return nil, err
		}
		left.Element = merged
	}
	return left, nil
}

func mergeArrayElementSchema(left, right *logschema.ValueSchema) (*logschema.ValueSchema, error) {
	if left.Type == right.Type {
		switch left.Type {
		case logschema.TypeObject:
			merged, err := mergeFields(left.Fields, right.Fields)
			if err != nil {
				return nil, err
			}
			left.Fields = merged
		case logschema.TypeArray:
			merged, err := mergeArrayElementSchema(left.Element, right.Element)
			if err != nil {
				return nil, err
			}
			left.Element = merged
		}
	} else {
		newType, ok := mergeType(left.Type, right.Type)
		if !ok {
			return nil, errors.Errorf("can't assign %s to %s", string(left.Type), string(right.Type))
		}
		left.Type = newType
	}
	return left, nil
}

// Checks if it is possible to merge the types
// It will returns the result of the merge. It will return false if the merging is not possible
func mergeType(from, to logschema.ValueType) (logschema.ValueType, bool) {
	switch from {
	case logschema.TypeBoolean:
		if to == logschema.TypeString || to == logschema.TypeBigInt || to == logschema.TypeFloat {
			return to, true
		}
		return from, false
	case logschema.TypeBigInt:
		if to == logschema.TypeString || to == logschema.TypeFloat {
			return to, true
		}
		return from, false
	case logschema.TypeFloat:
		if to == logschema.TypeString {
			return logschema.TypeString, true
		}
		if to == logschema.TypeBigInt {
			return logschema.TypeFloat, true
		}
		return from, false
	case logschema.TypeTimestamp:
		if to == logschema.TypeString {
			return to, true
		}
		return from, false
	case logschema.TypeString:
		if to == logschema.TypeArray || to == logschema.TypeObject {
			return from, false
		}
		return from, true
	default:
		return from, false
	}
}

func validateSchema(schema logschema.Schema, file string) error {
	desc := logtypes.Desc{
		Name:         "Custom.Test",
		Description:  "Custom log test schema",
		ReferenceURL: "-",
	}
	entry, err := customlogs.Build(desc, &schema)
	if err != nil {
		validationErrors := logschema.ValidationErrors(err)
		if len(validationErrors) > 0 {
			return errors.New(validationErrors[0].String())
		}
		return err
	}
	parser, err := entry.NewParser(nil)
	if err != nil {
		return err
	}

	fd, err := os.Open(file)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		_, err := parser.ParseLog(scanner.Text())
		if err != nil {
			return err
		}
	}
	if scanner.Err() != nil {
		return err
	}
	return nil
}
