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
	"regexp"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"" combined
// https://httpd.apache.org/docs/current/mod/mod_log_config.html#formats
// nolint:lll
type AccessCombined struct {
	AccessCommonLog
	UserAgent *string `json:"user_agent,omitempty" description:"The User-Agent HTTP header"`
	Referer   *string `json:"referer,omitempty" description:"The Referer HTTP header"`

	parsers.PantherLog
}

func (log *AccessCombined) ParseString(s string) error {
	match := rxAccessCombined.FindStringSubmatch(s)
	if len(match) > 1 {
		return log.SetRow(match[1:])
	}
	return errors.New("invalid access combined log")
}

var rxAccessCombined = regexp.MustCompile(buildRx(
	rxUnquoted,   // remoteIP
	rxUnquoted,   // clientID,
	rxUnquoted,   // userID,
	rxBrackets,   // requestTime
	rxQuoted,     // requestLine
	rxStatusCode, // responseStatus
	rxSize,       // responseSize
	rxQuoted,     // referer
	rxQuoted,     // userAgent
))

func (log *AccessCombined) SetRow(row []string) error {
	const fieldIndexReferer = 7
	const fieldIndexUserAgent = 8
	if len(row) == numFieldsAccessCombined {
		common, ref, ua := row[:numFieldsAccessCommon], row[fieldIndexReferer], row[fieldIndexUserAgent]
		if err := log.AccessCommonLog.SetRow(common); err != nil {
			return err
		}
		log.Referer = nonEmptyLogField(stripQuotes(ref))
		log.UserAgent = nonEmptyLogField(stripQuotes(ua))
		return nil
	}
	return errors.Errorf("invalid number of fields %d", len(row))
}

func (log *AccessCombined) updatePantherFields(p *parsers.PantherLog) {
	p.SetCoreFields(TypeAccessCombined, log.RequestTime, log)
	if !p.AppendAnyIPAddressPtr(log.RemoteHostIPAddress) {
		// Handle cases where apache config has resolved addresses enabled
		p.AppendAnyDomainNamePtrs(log.RemoteHostIPAddress)
	}
}

type AccessCombinedParser struct{}

var _ parsers.LogParser = (*AccessCombinedParser)(nil)

func NewAccessCombinedParser() parsers.LogParser {
	return &AccessCombinedParser{}
}
func (*AccessCombinedParser) New() parsers.LogParser {
	return NewAccessCombinedParser()
}
func (*AccessCombinedParser) LogType() string {
	return TypeAccessCombined
}
func (*AccessCombinedParser) Parse(log string) ([]*parsers.PantherLog, error) {
	combined := AccessCombined{}
	if err := combined.ParseString(log); err != nil {
		return nil, err
	}
	combined.updatePantherFields(&combined.PantherLog)
	return combined.Logs(), nil
}
