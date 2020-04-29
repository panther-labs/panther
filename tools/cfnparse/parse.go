package cfnparse

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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/magefile/mage/sh"
	"gopkg.in/yaml.v2"
)

var pythonVirtualEnvPath string

func init() {
	// When mage runs, the working directory is the root of the repo.
	// But when unit tests run, the working directory at the time of compilation is the package under test.
	//
	// We have to find the repo root to know where the python env (with cfn-flip) lives.
	path := "."
	for i := 1; i <= 10; i++ {
		if _, err := os.Stat(filepath.Join(path, "magefile.go")); err == nil {
			pythonVirtualEnvPath, err = filepath.Abs(filepath.Join(path, ".setup", "venv"))
			if err != nil {
				panic(err)
			}
			return
		}

		// Work our way up the file hierarchy
		path = filepath.Join(path, "..")
	}

	panic("couldn't find repo root")
}

// Parse a CloudFormation template, returning a json map.
//
// Short-form functions like "!If" and "!Sub" will be replaced with "Fn::" objects.
func ParseTemplate(path string) (map[string]interface{}, error) {
	if err := os.MkdirAll("out", 0755); err != nil {
		return nil, err
	}

	// The Go yaml parser doesn't understand short-form functions.
	// So we first use cfn-flip to flip .yml to .json
	if strings.ToLower(filepath.Ext(path)) != ".json" {
		jsonPath := filepath.Join("out", filepath.Base(path)+".json")
		if err := sh.Run(filepath.Join(pythonVirtualEnvPath, "bin", "cfn-flip"), "-j", path, jsonPath); err != nil {
			return nil, fmt.Errorf("failed to flip %s to json: %v", path, err)
		}
		defer os.Remove(jsonPath)
		path = jsonPath
	}

	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", path, err)
	}

	var result map[string]interface{}
	return result, jsoniter.Unmarshal(contents, &result)
}

// Save the CloudFormation structure as a .yml file.
func WriteTemplate(cfn map[string]interface{}, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", filepath.Dir(path), err)
	}

	contents, err := yaml.Marshal(cfn)
	if err != nil {
		return fmt.Errorf("yaml marshal failed: %v", err)
	}

	return ioutil.WriteFile(path, contents, 0644)
}
