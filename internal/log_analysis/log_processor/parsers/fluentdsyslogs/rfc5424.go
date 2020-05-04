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

const TypeRFC5424 = "Fluentd.Syslog5424"

var LogTypeRFC5424 = parsers.LogType{
	Name: TypeRFC5424,
	Description: `Fluentd syslog parser for the RFC5424 format (ie. BSD-syslog messages)
Reference: https://docs.fluentd.org/parser/syslog#rfc5424-log`,
	Schema: struct {
		RFC5424
		logs.Meta
	}{},
	NewParser: NewRFC5424Parser,
}

// nolint:lll
type RFC5424 struct {
	Priority  *uint8                      `json:"pri,omitempty" description:"Priority is calculated by (Facility * 8 + Severity). The lower this value, the higher importance of the log message."`
	Hostname  *string                     `json:"host,omitempty" validate:"required" description:"Hostname identifies the machine that originally sent the syslog message."`
	Ident     *string                     `json:"ident,omitempty" validate:"required" description:"Appname identifies the device or application that originated the syslog message."`
	ProcID    *numerics.Integer           `json:"pid,omitempty" validate:"required" description:"ProcID is often the process ID, but can be any value used to enable log analyzers to detect discontinuities in syslog reporting."`
	MsgID     *string                     `json:"msgid,omitempty" validate:"required" description:"MsgID identifies the type of message. For example, a firewall might use the MsgID 'TCPIN' for incoming TCP traffic."`
	ExtraData *string                     `json:"extradata,omitempty" validate:"required" description:"ExtraData contains syslog strucured data as string"`
	Message   *string                     `json:"message,omitempty" validate:"required" description:"Message contains free-form text that provides information about the event."`
	Timestamp *timestamp.FluentdTimestamp `json:"time,omitempty" validate:"required" description:"Timestamp of the syslog message in UTC."`
	Tag       *string                     `json:"tag,omitempty" validate:"required" description:"Tag of the syslog message"`
}

var _ parsers.PantherEventer = (*RFC5424)(nil)

// RFC5424Parser parses fluentd syslog logs in the RFC5424 format
type RFC5424Parser struct{}

var _ parsers.Interface = (*RFC5424Parser)(nil)

func NewRFC5424Parser() parsers.Interface {
	return &RFC5424Parser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *RFC5424Parser) Parse(log string) ([]*parsers.Result, error) {
	return parsers.QuickParseJSON(&RFC5424{}, log)
}

func (event *RFC5424) PantherEvent() *logs.Event {
	return logs.NewEvent(TypeRFC5424, event.Timestamp.UTC(),
		// The hostname should be a FQDN, but may also be an IP address. Check for IP, otherwise
		// add as a domain name. https://tools.ietf.org/html/rfc5424#section-6.2.4
		logs.HostnameP(event.Hostname),
		logs.IPAddressP(event.Message),
	)
}
