package build

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
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/iancoleman/strcase"
	"gopkg.in/yaml.v3"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes/logtesting"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/tools/mage/logger"
)

// Schemas exports the schemas and tests for native log types to out/schemas/
func Schemas() error {
	log := logger.Build("[build:schemas]")
	schemas, err := registry.ExportSchemas()
	if err != nil {
		return err
	}
	schemaTests := make(map[string][]logtesting.TestCase)
	scanForTests := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !strings.HasSuffix(info.Name(), "_tests.yml") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		dec := yaml.NewDecoder(f)
		for {
			testCase := logtesting.TestCase{}
			if err := dec.Decode(&testCase); err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			schemaTests[testCase.LogType] = append(schemaTests[testCase.LogType], testCase)
		}
	}
	if err := filepath.Walk("internal/log_analysis/log_processor/parsers", scanForTests); err != nil {
		return err
	}
	log.Infof("found %d log schemas and %d tests", len(schemas), len(schemaTests))
	outDir := "out/schemas/logs/"

	for name, schema := range schemas {
		data, err := yaml.Marshal(schema)
		if err != nil {
			return err
		}
		filename := path.Join(outDir, schemaOutputFilename(name))
		dirname := path.Dir(filename)
		if err := os.MkdirAll(dirname, 0755); err != nil {
			return err
		}

		if err := ioutil.WriteFile(filename, data, 0600); err != nil {
			return err
		}
		if err := writeTests(filename, schemaTests[name]); err != nil {
			return err
		}
	}
	return nil
}

func writeTests(filename string, testCases []logtesting.TestCase) error {
	if len(testCases) == 0 {
		return nil
	}
	filename = path.Join(
		path.Dir(filename),
		"tests",
		strings.Replace(path.Base(filename), ".yml", "_tests.yml", -1),
	)
	if err := os.MkdirAll(path.Dir(filename), 0755); err != nil {
		return err
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := yaml.NewEncoder(f)
	defer enc.Close()
	for _, testCase := range testCases {
		if err := enc.Encode(testCase); err != nil {
			return err
		}
	}
	return nil
}

func splitName(name string) (string, string) {
	if pos := strings.IndexByte(name, '.'); 0 <= pos && pos < len(name) {
		return name[:pos], name[pos+1:]
	}
	return "", name
}

func schemaOutputFilename(name string) string {
	group, name := splitName(name)
	return path.Join(strcase.ToSnake(group), strcase.ToSnake(name)+".yml")
}
