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
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
)

type InferOpts struct {
	SkipTest *bool
}

var inferJsoniter = jsoniter.Config{
	UseNumber: true,
}.Froze()

// Infers a schema given a sample of logs
func Infer(logger *zap.Logger, opts *InferOpts) {
	inputFiles := flag.Args()
	if len(inputFiles) == 0 {
		logger.Fatal("You need to specify at least one file")
		flag.Usage()
	}

	var valueSchema *logschema.ValueSchema
	var err error
	for _, file := range inputFiles {
		valueSchema, err = inferFromFile(valueSchema, file)
		if err != nil {
			logger.Fatal("failed to generate schema", zap.Error(err))
		}
	}

	// Remove empty objects
	valueSchema = valueSchema.NonEmpty()

	if !*opts.SkipTest {
		// In order to validate that the schema generated is correct,
		// run the parser against the logs, fail in case of error
		for _, file := range inputFiles {
			if err = validateSchema(valueSchema, file); err != nil {
				logger.Fatal("failed while testing schema with file. You can specify '-skip-test' argument to skip this step", zap.Error(err))
			}
		}
	}

	schema, err := yaml.Marshal(logschema.Schema{Version: 0, Fields: valueSchema.Fields})
	if err != nil {
		logger.Fatal("failed to marshal schema", zap.Error(err))
	}
	fmt.Println(string(schema))
}

func inferFromFile(root *logschema.ValueSchema, file string) (*logschema.ValueSchema, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close() // nolint: errcheck

	reader := bufio.NewReader(f)
	lineNum := 0
	run := true
	for run {
		lineNum++
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				// Don't go through more lines, but make sure to process existing line
				run = false
			} else {
				return root, errors.Wrap(err, "failed while reading file")
			}
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var data map[string]interface{}
		if err = inferJsoniter.Unmarshal(line, &data); err != nil {
			return nil, errors.Wrapf(err, "failed to parse line [%d] as JSON", lineNum)
		}
		lineObject := logschema.InferJSONValueSchema(data)
		if lineObject.Type != logschema.TypeObject {
			return nil, errors.New("invalid schema")
		}
		root = logschema.Merge(root, lineObject)
	}

	return root, nil
}

// Validates the schema. It generates a parser of the provided schema
// and tries to parse the contents of the file.
func validateSchema(valueSchema *logschema.ValueSchema, file string) error {
	schema := &logschema.Schema{Version: 0, Fields: valueSchema.Fields}
	entry, err := customlogs.Build("Custom.Test", schema)
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

	reader := bufio.NewReader(fd)
	run := true
	for run {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// Don't go through more lines, but make sure to process existing line
				run = false
			} else {
				return errors.Wrap(err, "failed while reading file")
			}
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		if _, err = parser.ParseLog(line); err != nil {
			return err
		}
	}
	return nil
}
