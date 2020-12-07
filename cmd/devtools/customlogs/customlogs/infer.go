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
	"os"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
)

type InferOpts struct {
	File *string
}

func Infer(logger *zap.SugaredLogger, opts *InferOpts) error {
	fd, err := os.Open(*opts.File)
	if err != nil {
		return err
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)

	api := jsoniter.Config{
		UseNumber: true,
	}.Froze()

	for scanner.Scan() {
		line := scanner.Bytes()
		var data map[string]interface{}
		err := api.Unmarshal(line, &data)
		if err != nil {
			logger.Fatalf("failed to parse line as JSON")
		}
		inferFields([]string{}, data)
	}
	if err := scanner.Err(); err != nil {
		logger.Fatalf("failed")
	}
	return nil
}

func inferFields(path []string, event map[string]interface{}) []logschema.FieldSchema {
	var out []logschema.FieldSchema
	for key, value := range event {
		valueSchema, ok := inferValueSchema(append(path, key), value)
		if !ok {
			continue
		}
		findings.observeValueSchema(append(path, key), valueSchema)

		field := logschema.FieldSchema{
			Name:        key,
			Description: "The " + key,
			Required:    true,
			ValueSchema: *valueSchema,
		}
		out = append(out, field)
	}
	return out
}

func inferValueSchema(path []string, value interface{}) (*logschema.ValueSchema, bool) {
	typ := inferValueType(value)
	switch typ {
	case logschema.TypeArray:
		array := value.([]interface{})
		if len(array) == 0 {
			return nil, false
		}
		valueSchema, ok := inferValueSchema(path, array[0])
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
			Fields: inferFields(path, object),
		}, true
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

// schemaFindings observe column names across a schema and provide case sensitive mappings
type schemaFindings map[string]*finding

var findings = schemaFindings{}

func (c schemaFindings) observeValueSchema(path []string, schema *logschema.ValueSchema) {
	fullPath := strings.Join(path, ".")
	find, ok := c[fullPath]
	if !ok {
		find := &finding{
			times:   1,
			schemas: []*logschema.ValueSchema{schema},
		}
		c[fullPath] = find
		return
	}
	find.times++
	for i := range find.schemas {
		if find.schemas[i].Type == schema.Type && schema.Type != logschema.TypeObject {
			// no need to add
			// we
			return
		}
	}
	find.schemas = append(find.schemas, schema)
}

type finding struct {
	times   int
	schemas []*logschema.ValueSchema
}

func (c schemaFindings) generateSchema(numLines int) (*logschema.Schema, error) {

	return nil, nil
}
