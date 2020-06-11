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
	Description               string              `yaml:"Description"`
	DisplayName               string              `yaml:"DisplayName"`
	Enabled                   bool                `yaml:"Enabled"`
	Filename                  string              `yaml:"Filename"`
	PolicyID                  string              `yaml:"PolicyID"`
	RuleID                    string              `yaml:"RuleID"`
	GlobalID                  string              `yaml:"GlobalID"`
	ResourceTypes             []string            `yaml:"ResourceTypes"`
	LogTypes                  []string            `yaml:"LogTypes"`
	Reference                 string              `yaml:"Reference"`
	Runbook                   string              `yaml:"Runbook"`
	Severity                  string              `yaml:"Severity"`
	Suppressions              []string            `yaml:"Suppressions"`
	Tags                      []string            `yaml:"Tags"`
	Tests                     []Test              `yaml:"Tests"`
	DedupPeriodMinutes        int                 `yaml:"DedupPeriodMinutes"`
	Reports                   map[string][]string `yaml:"Reports"`
}

// Test is a unit test definition when parsing policies in a bulk upload.
type Test struct {
	ExpectedResult bool        `yaml:"ExpectedResult"`
	Name           string      `yaml:"Name"`
	Resource       interface{} `yaml:"Resource"`
	Log            interface{} `yaml:"Log"`
	ResourceType   string      `yaml:"ResourceType"`
	LogType        string      `yaml:"LogType"`
}
