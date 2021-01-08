package util

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"os"
	"path/filepath"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/magefile/mage/sh"
)

// Parse a CloudFormation template and unmarshal into the out parameter.
// The caller can pass map[string]interface{} or a struct if the format is known.
//
// Short-form functions like "!If" and "!Sub" will be replaced with "Fn::" objects.
func ParseTemplate(path string, out interface{}) error {
	// The Go yaml parser doesn't understand short-form functions.
	// So we first use cfn-flip to flip .yml to .json
	if strings.ToLower(filepath.Ext(path)) != ".json" {
		jsonPath := filepath.Join(os.TempDir(), filepath.Base(path)+".json")
		if err := sh.Run(PipPath("cfn-flip"), "-j", path, jsonPath); err != nil {
			return fmt.Errorf("failed to flip %s to json: %v", path, err)
		}
		defer os.Remove(jsonPath)
		path = jsonPath
	}

	return jsoniter.Unmarshal(MustReadFile(path), out)
}
