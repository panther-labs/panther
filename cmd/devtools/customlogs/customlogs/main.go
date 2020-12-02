package main

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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/cmd/opstools"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/customlogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logschema"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// CLI flags
var opts = struct {
	Schema *string
	Output *string
}{
	Schema: flag.String("s", "", "Schema file"),
	Output: flag.String("o", "", "Write parsed results to file (defaults to stdout)"),
}

func main() {
	opstools.SetUsage(`-s SCHEMA_FILE [-o OUTPUT_FILE] [INPUT_FILES...]`)
	flag.Parse()
	loggerConfig := zap.NewDevelopmentConfig()
	loggerConfig.DisableStacktrace = true
	loggerConfig.DisableCaller = true
	z, err := loggerConfig.Build()
	if err != nil {
		log.Fatalln("failed to start logger: ", err.Error())
	}
	logger := z.Sugar()
	schemaFile := *opts.Schema
	if schemaFile == "" {
		flag.Usage()
		log.Fatal("no schema file provided")
	}
	schemaData, err := ioutil.ReadFile(schemaFile)
	if err != nil {
		logger.Fatalf("failed to load schema file %q: %s", schemaFile, err)
	}
	schema := logschema.Schema{}
	if err := yaml.Unmarshal(schemaData, &schema); err != nil {
		logger.Fatalf("failed to parse schema file as YAML %q: %s", schemaFile, err)
	}
	desc := logtypes.Desc{
		Name:         "Custom.Test",
		Description:  fmt.Sprintf("Custom log test schema %s", schemaFile),
		ReferenceURL: "-",
	}
	entry, err := customlogs.Build(desc, &schema)
	if err != nil {
		validationErrors := logschema.ValidationErrors(err)
		if len(validationErrors) > 0 {
			logger.Error("Schema validation failed:")
			for _, e := range validationErrors {
				logger.Errorf("  - %s", e.String())
			}
		}
		logger.Fatalf("Failed to build schema %q: %s\n", schemaFile, err)
	}
	parser, err := entry.NewParser(nil)
	if err != nil {
		logger.Fatalf("failed to build parser: %s", err)
	}
	outFile := *opts.Output
	var out io.Writer
	if outFile == "" {
		out = os.Stdout
	} else {
		f, err := os.Open(outFile)
		if err != nil {
			logger.Fatalf("failed to open output file: %s\r", err)
		}
		defer f.Close() // nolint: errcheck
		out = f
	}
	inputFiles := flag.Args()
	if len(inputFiles) == 0 {
		inputFiles = []string{"-"}
	}
	numResults, numErrors := parseFiles(parser, logger, out, inputFiles...)
	logger.Infof("Done %d results, %d errors\n", numResults, numErrors)
}

func parseFiles(parser parsers.Interface, logger *zap.SugaredLogger, w io.Writer, files ...string) (numResults int, numErrors int) {
	for _, testFile := range files {
		var file io.Reader
		if testFile == "-" {
			file = os.Stdin
		} else {
			f, err := os.Open(testFile)
			if err != nil {
				logger.Fatalf("failed to open test file %q: %s", testFile, err)
			}
			defer f.Close() // nolint: errcheck
			file = f
		}
		scanner := bufio.NewScanner(file)
		lineNum := 0
		jsonAPI := pantherlog.ConfigJSON()
		for scanner.Scan() {
			line := scanner.Text()
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			results, err := parser.ParseLog(line)
			if err != nil {
				numErrors++
				logger.Errorf("Parse error at line %d: %s", lineNum, err)
				logger.Debug("line", line)
			}
			for _, result := range results {
				data, err := jsonAPI.MarshalToString(result)
				if err != nil {
					logger.Fatalf("failed to marshal result: %s\n", err)
				}
				if _, err := fmt.Fprintln(w, data); err != nil {
					logger.Fatalf("failed to write output: %s\n", err)
				}
				numResults++
			}
			lineNum++
		}
	}
	return numResults, numErrors
}
