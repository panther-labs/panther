package parsers

import "github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"

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

// AdapterFactory returns a pantherlog.LogParserFactory from a parsers.Parser
// This is used to ease transition to the new parsers.Interface for parsers based on parsers.PantherLog
func AdapterFactory(parser LogParser) pantherlog.FactoryFunc {
	return func(_ interface{}) (Interface, error) {
		return NewAdapter(parser), nil
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

func (a *logParserAdapter) ParseLog(log string) ([]*Result, error) {
	results, err := a.LogParser.Parse(log)
	if err != nil {
		return nil, err
	}
	return ToResults(results, nil)
}
