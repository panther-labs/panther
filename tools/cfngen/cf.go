// Package cfngen generates CloudFormation from Go objects.
package cfngen

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"bytes"
	"io"
	"regexp"

	jsoniter "github.com/json-iterator/go"
)

// FIXME: consider replacing this with CDK when a Go version is available.

// enable compatibility with encoding/json
var json = jsoniter.ConfigCompatibleWithStandardLibrary

// Represents a CF reference
type Ref struct {
	Ref string
}

// Represents a simple CF Fn::Sub using template params
type Sub struct {
	Sub string `json:"Fn::Sub"`
}

// Represents CF Parameter
type Parameter struct {
	Type          string
	Default       interface{}   `json:",omitempty"`
	Description   string        `json:",omitempty"`
	AllowedValues []interface{} `json:",omitempty"`
	MinValue      interface{}   `json:",omitempty"`
	MaxValue      interface{}   `json:",omitempty"`
}

type Output struct {
	Description string
	Value       interface{}
}

// Represents a CF template
type Template struct {
	AWSTemplateFormatVersion string
	Description              string                 `json:",omitempty"`
	Parameters               map[string]interface{} `json:",omitempty"`
	Resources                map[string]interface{} `json:",omitempty"`
	Outputs                  map[string]interface{} `json:",omitempty"`
}

// Emit CF as JSON to io.Writer
func (t *Template) WriteCloudFormation(w io.Writer) (err error) {
	jsonBytes, err := json.MarshalIndent(t, "", " ")
	if err != nil {
		return err
	}
	_, err = w.Write(jsonBytes)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("\n")) // add trailing \n that is expected in text files
	return
}

// Emit CF as JSON return []bytes
func (t *Template) CloudFormation() ([]byte, error) {
	buffer := bytes.Buffer{}
	err := t.WriteCloudFormation(&buffer)
	return buffer.Bytes(), err
}

// Create a CF template , use WriteCloudFormation() to emit.
func NewTemplate(description string, parameters map[string]interface{}, resources map[string]interface{},
	outputs map[string]interface{}) (t *Template) {

	t = &Template{
		AWSTemplateFormatVersion: "2010-09-09",
		Description:              description,
		Parameters:               parameters,
		Resources:                resources,
		Outputs:                  outputs,
	}
	return
}

// Re-map characters not allowed in CF names consistently (CF resources must be alphanumeric)
var sanitizeResourceName = regexp.MustCompile(`([^[:alnum:]])`)

func SanitizeResourceName(name string) string {
	return sanitizeResourceName.ReplaceAllString(name, "")
}
