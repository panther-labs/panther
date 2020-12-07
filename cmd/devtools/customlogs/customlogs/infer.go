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
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

type InferOpts struct {
	File *string
}

var inferJsoniter = jsoniter.Config{
	UseNumber: true,
}.Froze()

func Infer(logger *zap.SugaredLogger, opts *InferOpts) {
	fd, err := os.Open(*opts.File)
	if err != nil {
		logger.Fatal("failed to read input file", zap.Error(err))
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	var globalSchemaFields []logschema.FieldSchema
	counter := 0
	for scanner.Scan() {
		counter++
		globalSchemaFields, err = processLine(scanner.Bytes(), globalSchemaFields)
		if err != nil {
			logger.Fatal("failed while inferring schema",
				zap.Int("lineNum", counter),
				zap.Error(err))
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Fatal("failed to read input file", zap.Error(err))
	}
	marshalled, err := yaml.Marshal(globalSchemaFields)
	if err != nil {
		logger.Fatal("failed to marshal result", zap.Error(err))
	}
	fmt.Println(string(marshalled))
}

func processLine(line []byte, globalFields []logschema.FieldSchema) ([]logschema.FieldSchema, error) {
	var data map[string]interface{}
	err := inferJsoniter.Unmarshal(line, &data)
	if err != nil {
		return globalFields, errors.Wrap(err, "failed to parse line as JSON")
	}
	return mergeFields(globalFields, inferFields(data))
}

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
	// sorts the fields by name
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func inferValueSchema(value interface{}) (*logschema.ValueSchema, bool) {
	typ := inferValueType(value)
	switch typ {
	case logschema.TypeArray:
		array := value.([]interface{})
		if len(array) == 0 {
			return nil, false
		}
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

func inferValueType(value interface{}) logschema.ValueType {
	switch value.(type) {
	case bool:
		return logschema.TypeBoolean
	case string:
		return logschema.TypeString
	case json.Number:
		value := value.(json.Number)
		if _, err := value.Int64(); err != nil {
			return logschema.TypeFloat
		}
		return logschema.TypeBigInt
	case map[string]interface{}:
		return logschema.TypeObject
	case []interface{}:
		return logschema.TypeArray
	default:
		panic("Doesn't work")
	}
}

func guessStringValue(value string) *logschema.ValueSchema {
	// If we could parse it as boolean,
	// return it as boolean
	if err := (&pantherlog.Bool{}).UnmarshalJSON([]byte(value)); err == nil {
		return &logschema.ValueSchema{
			Type: logschema.TypeBoolean,
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
			leftValue.Required = false
			continue
		}

		merged, err := mergeFieldSchema(&leftValue, &rightValue)
		if err != nil {
			return nil, err
		}
		leftMap[key] = *merged
		delete(rightMap, key)
	}

	for key, value := range rightMap {
		// Since this was not found on the left, mark it as optional
		value.Required = false
		leftMap[key] = value
	}

	var out []logschema.FieldSchema
	for _, value := range leftMap {
		out = append(out, value)
	}
	return out, nil
}

func mergeFieldSchema(left, right *logschema.FieldSchema) (*logschema.FieldSchema, error) {
	if left.Type == right.Type {
		switch left.Type {
		case logschema.TypeObject:
			merged, err := mergeFields(left.Fields, right.Fields)
			if err != nil {
				return nil, err
			}
			left.Fields = merged
		case logschema.TypeArray:
			merged, err := mergeValueSchema(left.Element, right.Element)
			if err != nil {
				return nil, err
			}
			left.Element = merged
		}
	} else {
		if assignable(left.Type, right.Type) {
			left.Type = right.Type
		} else {
			return nil, errors.Errorf("can't assign %s to %s", string(left.Type), string(right.Type))
		}
	}
	return left, nil
}

func mergeValueSchema(left, right *logschema.ValueSchema) (*logschema.ValueSchema, error) {
	if left.Type == right.Type {
		switch left.Type {
		case logschema.TypeObject:
			merged, err := mergeFields(left.Fields, right.Fields)
			if err != nil {
				return nil, err
			}
			left.Fields = merged
		case logschema.TypeArray:
			merged, err := mergeValueSchema(left.Element, right.Element)
			if err != nil {
				return nil, err
			}
			left.Element = merged
		}
	} else {
		if assignable(left.Type, right.Type) {
			left.Type = right.Type
		} else {
			return nil, errors.Errorf("can't assign %s to %s", string(left.Type), string(right.Type))
		}
	}
	return left, nil
}

func assignable(from, to logschema.ValueType) bool {
	switch from {
	case logschema.TypeBoolean:
		return to == logschema.TypeString || to == logschema.TypeBigInt || to == logschema.TypeFloat
	case logschema.TypeBigInt:
		return to == logschema.TypeString || to == logschema.TypeFloat
	case logschema.TypeTimestamp:
		return to == logschema.TypeString
	default:
		return false
	}
}
