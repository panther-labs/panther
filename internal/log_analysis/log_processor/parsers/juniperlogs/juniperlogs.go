// Package juniperlogs provides parsers for Juniper logs
package juniperlogs

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
)

const (
	rxBrackets  = `\[[^\]]*\]`
	rxQuoted    = `"[^"]*"`
	rxTimestamp = `\w+ \d+ \d{2}:\d{2}:\d{2}`
	rxLogLevel  = `\[(?:TRACE|DEBUG|INFO|WARN|ERROR)\]`
)

type timestampParser struct {
	Now time.Time
}

// ParseTimestamp parses juniper log timestamps.
// Juniper innovated in their log format by omitting the year.
// This makes parsing the logs more fun especially if we're around New Year's eve.
// This parser tries to guess the year of the log event by comparing the year at the time of parsing.
func (p *timestampParser) ParseTimestamp(s string) (time.Time, error) {
	const layoutTimestamp = `Jan 2 15:04:05`
	tm, err := time.ParseInLocation(layoutTimestamp, s, time.UTC)
	if err != nil {
		return time.Time{}, err
	}
	year, month := p.Now.Year(), p.Now.Month()
	if month == time.January && tm.Month() > month {
		year--
	}
	return tm.AddDate(year, 0, 0), nil
}
