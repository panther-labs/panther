package analysis

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

// Config defines the file format when parsing a bulk upload.
//
// YAML tags required because the YAML unmarshaller needs them
// JSON tags not present because the JSON unmarshaller is easy
type Config struct {
	AnalysisType              string              `yaml:"AnalysisType"`
	AutoRemediationID         string              `yaml:"AutoRemediationID"`
	AutoRemediationParameters map[string]string   `yaml:"AutoRemediationParameters"`
	DataModelID               string              `yaml:"DataModelID"`
	DedupPeriodMinutes        int                 `yaml:"DedupPeriodMinutes"`
	Description               string              `yaml:"Description"`
	DisplayName               string              `yaml:"DisplayName"`
	Enabled                   bool                `yaml:"Enabled"`
	Filename                  string              `yaml:"Filename"`
	GlobalID                  string              `yaml:"GlobalID"`
	LogTypes                  []string            `yaml:"LogTypes"`
	Mappings                  []Mapping           `yaml:"Mappings"`
	OutputIds                 []string            `yaml:"OutputIds"`
	PolicyID                  string              `yaml:"PolicyID"`
	Reference                 string              `yaml:"Reference"`
	Reports                   map[string][]string `yaml:"Reports"`
	ResourceTypes             []string            `yaml:"ResourceTypes"`
	RuleID                    string              `yaml:"RuleID"`
	Runbook                   string              `yaml:"Runbook"`
	Severity                  string              `yaml:"Severity"`
	Suppressions              []string            `yaml:"Suppressions"`
	Tags                      []string            `yaml:"Tags"`
	Tests                     []Test              `yaml:"Tests"`
	Threshold                 int                 `yaml:"Threshold"`
}

// Mapping converts source log field name to standard field name.
type Mapping struct {
	Path   string `yaml:"Path"`
	Method string `yaml:"Method"`
	Name   string `yaml:"Name"`
}

// Test is a unit test definition when parsing policies in a bulk upload.
type Test struct {
	ExpectedResult bool        `yaml:"ExpectedResult"`
	Log            interface{} `yaml:"Log"`
	LogType        string      `yaml:"LogType"`
	Name           string      `yaml:"Name"`
	Resource       interface{} `yaml:"Resource"`
	ResourceType   string      `yaml:"ResourceType"`
}

// PackConfig is specifically for pack definitions
type PackConfig struct {
	AnalysisType   string         `yaml:"AnalysisType"`
	Description    string         `yaml:"Description"`
	PackDefinition PackDefinition `yaml:"PackDefinition"`
	DisplayName    string         `yaml:"DisplayName"`
	PackID         string         `yaml:"PackID"`
}

// DetectionPattern defines what makes up a pack
type PackDefinition struct {
	IDs []string `yaml:"IDs"`
}
