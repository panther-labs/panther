package parsers

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
	jsoniter "github.com/json-iterator/go"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/jsonutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
)

// LogParser represents a parser for a supported log type
// NOTE: We will be transitioning parsers to the `pantherlog.LogParser` interface.
// Until all parsers are converted to the new interface the `AdapterFactory()` helper should be used
// when registering a `pantherlog.EventTypeEntry` that uses this interface.
type LogParser interface {
	// EventTypeEntry returns the log type supported by this parser
	LogType() string

	// Parse attempts to parse the provided log line
	// If the provided log is not of the supported type the method returns nil and an error
	Parse(log string) ([]*PantherLog, error)

	// New returns a new instance of the log parser, used like a factory method for stateful parsers
	New() LogParser
}

// Validator can be used to validate schemas of log fields
var Validator = validator.New()

// JSON is a custom jsoniter config to properly remap field names for compatibility with Athena views
var JSON = func() jsoniter.API {
	config := jsoniter.Config{
		EscapeHTML: true,
		// Validate raw JSON messages to make sure queries work as expected
		ValidateJsonRawMessage: true,
		// We don't need sorted map keys
		SortMapKeys: false,
	}
	api := config.Froze()
	rewriteFields := jsonutil.NewEncoderNamingStrategy(awsglue.RewriteFieldName)
	api.RegisterExtension(rewriteFields)
	return api
}()

// AdapterFactory returns a pantherlog.LogParser factory from a parsers.Parser
// This is used to ease transition to the new pantherlog.EventTypeEntry registry.
func AdapterFactory(parser LogParser) pantherlog.LogParserFactory {
	return func(_ interface{}) pantherlog.LogParser {
		return NewAdapter(parser)
	}
}

// NewAdapter creates a pantherlog.LogParser from a parsers.Parser
func NewAdapter(parser LogParser) pantherlog.LogParser {
	return &logParserAdapter{
		LogParser: parser.New(),
	}
}

type logParserAdapter struct {
	LogParser
}

func (a *logParserAdapter) ParseLog(log string) ([]*pantherlog.Result, error) {
	return ToResults(a.LogParser.Parse(log))
}
