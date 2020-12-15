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
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

// LogParser represents a parser for a supported log type
// NOTE: We will be transitioning parsers to the `parsers.Interface` interface.
// Until all parsers are converted to the new interface the `AdapterFactory()` helper should be used
// when registering a new log type to a `logtypes.Registry`
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
var Validator = NewValidator()

// NewValidator creates a validator.Validate instance that knows how to handle the types used in panther logs.
func NewValidator() *validator.Validate {
	v := validator.New()
	null.RegisterValidators(v)
	return v
}

// Interface is the interface to be used for log parsers.
type Interface = pantherlog.LogParser

// Result is the result of parsing a log event.
// It is an alias of `pantherlog.Result` to help with the refactoring.
type Result = pantherlog.Result
