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
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeMWS = `Juniper.MWS`

type MWSParser struct {
	timestampParser
}

func (p *MWSParser) LogType() string {
	return TypeMWS
}
func (p *MWSParser) New() parsers.LogParser {
	return NewMWSParser()
}
func NewMWSParser() *MWSParser {
	return &MWSParser{
		timestampParser: timestampParser{
			Now: time.Now(),
		},
	}
}

func (p *MWSParser) Parse(log string) ([]*parsers.PantherLog, error) {
	match := rxMWS.FindStringSubmatch(log)
	if len(match) == 0 {
		return nil, errors.New("invalid log line")
	}
	if _, skip := mwsSkipServices[match[4]]; skip {
		return nil, errors.New("skip log line")
	}
	fields := struct {
		Timestamp string
		Hostname  string
		LogLevel  string
		Service   string
		Component string
		Message   string
	}{
		Timestamp: match[1],
		Hostname:  match[2],
		LogLevel:  match[3],
		Service:   strings.Trim(match[4], "[]"),
		Component: match[5],
		Message:   strings.TrimSpace(match[6]),
	}
	ts, err := p.ParseTimestamp(fields.Timestamp)
	if err != nil {
		return nil, err
	}

	event := MWS{
		Timestamp:   timestamp.RFC3339(ts),
		Hostname:    fields.Hostname,
		ServiceName: fields.Service,
		Message:     fields.Message,
	}

	if fields.LogLevel != "" {
		logLevel := strings.Trim(fields.LogLevel, "[]")
		event.LogLevel = &logLevel
	}

	if fields.Component != "" {
		component := strings.Trim(fields.Component, "[]")
		event.ServiceComponent = &component
	}

	event.SetCoreFields(TypeMWS, &event.Timestamp, &event)
	return event.Logs(), nil
}

// Service tags that not handled by MWSParser
var mwsSkipServices = map[string]struct{}{
	"[mws-access]":         {},
	"[mws-security-alert]": {},
	"[mws-audit]":          {},
}

// nolint:lll
type MWS struct {
	Timestamp        timestamp.RFC3339 `json:"timestamp,omitempty" description:"The date of the log entry, in UTC."`
	Hostname         string            `json:"hostname,omitempty" description:"The appliance hostname."`
	LogLevel         *string           `json:"log_level,omitempty" description:"The importance level of a log entry. Can be TRACE, DEBUG, INFO, WARN, or ERROR."`
	ServiceName      string            `json:"service_name,omitempty" description:"The WebApp Secure service that generated the log entry."`
	ServiceComponent *string           `json:"service_component,omitempty" description:"The specific component that is issuing the log message."`
	Message          string            `json:"log_message,omitempty" description:"The message. This can be anything, but usually contains information to help you narrow down problems or confirm certain events have occurred as they should."`

	parsers.PantherLog
}

var rxMWS = regexp.MustCompile(fmt.Sprintf(
	`^(%s) (\S+) (%s)?\s*(%s)\s*(%s)?:?\s*(.*)$`,
	rxTimestamp,
	rxLogLevel, // log level
	rxBrackets, // service name
	rxBrackets, // service component
))
