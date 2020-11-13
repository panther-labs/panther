// Package apachelogs contains parsers for logs of the Apache HTTP Server
package apachelogs

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
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

const (
	TypeAccessCombined = `Apache.AccessCombined`
	TypeAccessCommon   = `Apache.AccessCommon`
)

// LogTypes exports the available log type entries
func LogTypes() logtypes.Group {
	return logTypes
}

var logTypes = logtypes.Must("Apache",
	logtypes.Config{
		Name:         TypeAccessCombined,
		Description:  `Apache HTTP server access logs using the 'combined' format`,
		ReferenceURL: `https://httpd.apache.org/docs/current/logs.html#combined`,
		Schema:       AccessCombined{},
		NewParser:    parsers.AdapterFactory(NewAccessCombinedParser()),
	},
	logtypes.Config{
		Name:         TypeAccessCommon,
		Description:  `Apache HTTP server access logs using the 'common' format`,
		ReferenceURL: `https://httpd.apache.org/docs/current/logs.html#common`,
		Schema:       AccessCommon{},
		NewParser:    parsers.AdapterFactory(NewAccessCommonParser()),
	},
)

// 	[day/month/year:hour:minute:second zone]
// day = 2*digit
// month = 3*letter
// year = 4*digit
// hour = 2*digit
// minute = 2*digit
// second = 2*digit
// zone = (`+' | `-') 4*digit
const layoutApacheTimestamp = `[02/Jan/2006:15:04:05 -0700]`

const (
	numFieldsAccessCombined = 9
	numFieldsAccessCommon   = 7
)

// field regular expressions to be used in buildRx
const (
	rxUnquoted   = `[^\s]+`            // match a sequence of non space character
	rxBrackets   = `\[[^\]]+\]`        // match a sequence of characters surrounded by square brackets
	rxQuoted     = `"(?:[^"\\]|\\")*"` // match a sequence of character surrounded by double quotes skipping escaped quotes
	rxStatusCode = `\d{3}`             // match 3 digits
	rxSize       = `-|\d+`             // match '-' or a series of digits
)

func buildRx(rxFields ...string) string {
	groups := make([]string, len(rxFields))
	for i, field := range rxFields {
		groups[i] = fmt.Sprintf("(%s)", field)
	}
	return fmt.Sprintf(`^\s*%s\s*$`, strings.Join(groups, `\s+`))
}

func nonEmptyLogField(s string) *string {
	switch s {
	case "", "-", "\"-\"":
		return nil
	default:
		return &s
	}
}

// httpRequestLine is the HTTP request line from an HTTP request.
type httpRequestLine struct {
	Method   string
	URI      string
	Protocol string
}

// ParseString parses an HTTP request line from a string.
func (r *httpRequestLine) ParseString(s string) error {
	s = strings.TrimSpace(s)
	s = stripQuotes(s)
	s = strings.TrimSpace(s)
	parts := rxSplitSpace.Split(s, -1)
	if len(parts) == 3 {
		*r = httpRequestLine{
			Method:   parts[0],
			URI:      parts[1],
			Protocol: parts[2],
		}
		return nil
	}
	return errors.New("invalid request line")
}

var rxSplitSpace = regexp.MustCompile(`\s+`)

// stripQuotes strips the first and last character off a string if they are `"`
func stripQuotes(line string) string {
	if len(line) > 0 && line[0] == '"' {
		tail := line[1:]
		if last := len(tail) - 1; 0 <= last && last < len(tail) && tail[last] == '"' {
			return tail[:last]
		}
	}
	return line
}
