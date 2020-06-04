// Package pantherlog defines types and functions to parse logs for Panther
package pantherlog

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
	"net/url"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/api/lambda/core/log_analysis/log_processor/models"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
)

const FieldPrefix = "p_"

// LogType describes a log type.
// It provides a method to create a new parser and a schema struct to derive tables from.
// LogTypes can be grouped in a `Registry` to have an index of available log types.
type LogType struct {
	Name         string
	Description  string
	ReferenceURL string
	// A struct value that matches the JSON in the results returned by the LogParser.
	Schema interface{}
	// Factory for new LogParser instances that return results for this log type.
	NewParser func() LogParser

	glueTableMetadata *awsglue.GlueTableMetadata
}

// LogParser is the interface to be used for log entry parsers.
type LogParser interface {
	ParseLog(log string) ([]*Result, error)
}

func (t *LogType) GlueTableMetadata() *awsglue.GlueTableMetadata {
	return t.glueTableMetadata
}

// Parser returns a new LogParser instance for this log type
func (t *LogType) Parser() LogParser {
	return t.NewParser()
}

// Check verifies a log type is valid
func (t *LogType) Check() error {
	if t == nil {
		return errors.Errorf("nil log type entry")
	}
	if t.Name == "" {
		return errors.Errorf("missing entry log type")
	}
	if t.Description == "" {
		return errors.Errorf("missing description for log type %q", t.Name)
	}
	if t.ReferenceURL == "" {
		return errors.Errorf("missing reference URL for log type %q", t.Name)
	}
	if t.ReferenceURL != "-" {
		u, err := url.Parse(t.ReferenceURL)
		if err != nil {
			return errors.Wrapf(err, "invalid reference URL for log type %q", t.Name)
		}
		switch u.Scheme {
		case "http", "https":
		default:
			return errors.Wrapf(err, "invalid reference URL scheme %q for log type %q", u.Scheme, t.Name)
		}
	}

	t.glueTableMetadata = awsglue.NewGlueTableMetadata(models.LogData, t.Name, t.Description, awsglue.GlueTableHourly, t.Schema)

	return checkLogEntrySchema(t.Name, t.Schema)
}

func checkLogEntrySchema(logType string, schema interface{}) error {
	if schema == nil {
		return errors.Errorf("nil schema for log type %q", logType)
	}
	data, err := jsoniter.Marshal(schema)
	if err != nil {
		return errors.Errorf("invalid schema struct for log type %q: %s", logType, err)
	}
	var fields map[string]interface{}
	if err := jsoniter.Unmarshal(data, &fields); err != nil {
		return errors.Errorf("invalid schema struct for log type %q: %s", logType, err)
	}
	// TODO: [parsers] Use reflect to check provided schema struct for required panther fields
	return nil
}
