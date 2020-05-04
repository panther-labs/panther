package fluentdsyslogs

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/logs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeRFC3164 = "Fluentd.Syslog3164"

var LogTypeRFC3164 = parsers.LogType{
	Name: TypeRFC3164,
	Description: `Fluentd syslog parser for the RFC3164 format (ie. BSD-syslog messages)
Reference: https://docs.fluentd.org/parser/syslog#rfc3164-log`,
	Schema: struct {
		RFC3164
		logs.Meta
	}{},
	NewParser: NewRFC3164Parser,
}

// nolint:lll
type RFC3164 struct {
	Priority  *uint8                      `json:"pri" description:"Priority is calculated by (Facility * 8 + Severity). The lower this value, the higher importance of the log message."`
	Hostname  *string                     `json:"host,omitempty" validate:"required" description:"Hostname identifies the machine that originally sent the syslog message."`
	Ident     *string                     `json:"ident,omitempty" validate:"required" description:"Appname identifies the device or application that originated the syslog message."`
	ProcID    *numerics.Integer           `json:"pid,omitempty" description:"ProcID is often the process ID, but can be any value used to enable log analyzers to detect discontinuities in syslog reporting."`
	Message   *string                     `json:"message,omitempty" validate:"required" description:"Message contains free-form text that provides information about the event."`
	Timestamp *timestamp.FluentdTimestamp `json:"time,omitempty" validate:"required" description:"Timestamp of the syslog message in UTC."`
	Tag       *string                     `json:"tag,omitempty" validate:"required" description:"Tag of the syslog message"`
}

var _ parsers.PantherEventer = (*RFC3164)(nil)

// RFC3164Parser parses Fluentd syslog logs in the RFC3164 format
type RFC3164Parser struct{}

var _ parsers.Interface = (*RFC3164Parser)(nil)

func NewRFC3164Parser() parsers.Interface {
	return &RFC3164Parser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *RFC3164Parser) Parse(log string) ([]*parsers.Result, error) {
	return parsers.QuickParseJSON(&RFC3164{}, log)
}

func (event *RFC3164) PantherEvent() *logs.Event {
	return logs.NewEvent(TypeRFC3164, event.Timestamp.UTC(),
		// The hostname should be a FQDN, but may also be an IP address. Check for IP, otherwise
		// add as a domain name. https://tools.ietf.org/html/rfc5424#section-6.2.4
		logs.HostnameP(event.Hostname),
		logs.IPAddressP(event.Message),
	)
}
