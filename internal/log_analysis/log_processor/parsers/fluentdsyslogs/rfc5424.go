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
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

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
	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// RFC5424Parser parses fluentd syslog logs in the RFC5424 format
type RFC5424Parser struct{}

var _ parsers.LogParser = (*RFC5424Parser)(nil)

func (p *RFC5424Parser) New() parsers.LogParser {
	return &RFC5424Parser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *RFC5424Parser) Parse(log string) ([]*parsers.PantherLog, error) {
	rfc5424 := &RFC5424{}

	err := jsoniter.UnmarshalFromString(log, rfc5424)
	if err != nil {
		return nil, err
	}

	rfc5424.updatePantherFields(p)

	if err := parsers.Validator.Struct(rfc5424); err != nil {
		return nil, err
	}

	return rfc5424.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *RFC5424Parser) LogType() string {
	return TypeRFC5424
}

func (event *RFC5424) updatePantherFields(p *RFC5424Parser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.Timestamp), event)

	// The hostname should be a FQDN, but may also be an IP address. Check for IP, otherwise
	// add as a domain name. https://tools.ietf.org/html/rfc5424#section-6.2.4
	if !event.AppendAnyIPAddressPtr(event.Hostname) {
		event.AppendAnyDomainNamePtrs(event.Hostname)
	}

	event.AppendAnyIPAddressInFieldPtr(event.Message)
}
