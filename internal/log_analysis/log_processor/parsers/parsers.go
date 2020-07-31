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
	"time"

	jsoniter "github.com/json-iterator/go"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/jsonutil"
)

// LogParser represents a parser for a supported log type
// NOTE: We will be transitioning parsers to the `pantherlog.LogParser` interface.
// Until all parsers are converted to the new interface the `AdapterFactory()` helper should be used
// when registering a `logtypes.Entry` that uses this interface.
type LogParser interface {
	// LogType returns the log type supported by this parser
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
	// Use proper glue columns names for fields
	rewriteFields := jsonutil.NewEncoderNamingStrategy(awsglue.RewriteFieldName)
	api.RegisterExtension(rewriteFields)
	return api
}()

// Interface is the interface to be used for log parsers.
type Interface interface {
	ParseLog(log string) ([]*Result, error)
}

// Result is the result of parsing a log event.
// It contains the JSON form of the pantherlog to be stored for queries.
type Result struct {
	LogType   string
	EventTime time.Time
	JSON      []byte
}

// Results wraps a single Result in a slice.
func (r *Result) Results() []*Result {
	if r == nil {
		return nil
	}
	return []*Result{r}
}

// Factory creates new parser instances.
// The params argument defines parameters for a parser.
type Factory func(params interface{}) (Interface, error)

// AdapterFactory returns a pantherlog.LogParser factory from a parsers.Parser
// This is used to ease transition to the new pantherlog.EventTypeEntry registry.
func AdapterFactory(parser LogParser) Factory {
	return func(_ interface{}) (Interface, error) {
		return NewAdapter(parser), nil
	}
}

// NewAdapter creates a pantherlog.LogParser from a parsers.Parser
func NewAdapter(parser LogParser) Interface {
	return &logParserAdapter{
		LogParser: parser.New(),
	}
}

type logParserAdapter struct {
	LogParser
}

func (a *logParserAdapter) ParseLog(log string) ([]*Result, error) {
	return ToResults(a.LogParser.Parse(log))
}
