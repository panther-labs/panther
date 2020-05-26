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
)

// LogParser represents a parser for a supported log type
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

// JSON re-exports pantherlog.JSON
var JSON = pantherlog.JSON

type Interface interface {
	ParseLog(log string) ([]*pantherlog.Result, error)
}

type logParserAdapter struct {
	LogParser
}

func (a *logParserAdapter) ParseLog(log string) ([]*pantherlog.Result, error) {
	logs, err := a.LogParser.Parse(log)
	if err != nil {
		return nil, err
	}
	results := make([]*pantherlog.Result, len(logs))
	for i := range results {
		result, err := logs[i].Result()
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}

func NewAdapter(parser LogParser) Interface {
	return &logParserAdapter{
		LogParser: parser.New(),
	}
}

func AdapterFactory(parser LogParser) ParserFactory {
	return func() Interface {
		return &logParserAdapter{
			LogParser: parser.New(),
		}
	}
}
