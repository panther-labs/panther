package sysloglogs

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

	"github.com/influxdata/go-syslog/v3"
	"github.com/influxdata/go-syslog/v3/rfc3164"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// nolint:lll
type RFC3164 struct {
	Priority  *uint8             `json:"priority" validate:"required" description:"Priority is calculated by (Facility * 8 + Severity). The lower this value, the higher importance of the log message."`
	Facility  *uint8             `json:"facility" validate:"required" description:"Facility value helps determine which process created the message. Eg: 0 = kernel messages, 3 = system daemons."`
	Severity  *uint8             `json:"severity" validate:"required" description:"Severity indicates how severe the message is. Eg: 0=Emergency to 7=Debug."`
	Timestamp *timestamp.RFC3339 `json:"timestamp,omitempty" description:"Timestamp of the syslog message in UTC."`
	Hostname  *string            `json:"hostname,omitempty" description:"Hostname identifies the machine that originally sent the syslog message."`
	Appname   *string            `json:"appname,omitempty" description:"Appname identifies the device or application that originated the syslog message."`
	ProcID    *string            `json:"procid,omitempty" description:"ProcID is often the process ID, but can be any value used to enable log analyzers to detect discontinuities in syslog reporting."`
	MsgID     *string            `json:"msgid,omitempty" description:"MsgID identifies the type of message. For example, a firewall might use the MsgID 'TCPIN' for incoming TCP traffic."`
	Message   *string            `json:"message,omitempty" description:"Message contains free-form text that provides information about the event."`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// RFC3164Parser parses Syslog logs in the RFC3164 format
type RFC3164Parser struct {
	parser syslog.Machine
}

// New returns an initialized LogParser for Syslog RFC3164 logs
func (p *RFC3164Parser) New() parsers.LogParser {
	return &RFC3164Parser{
		parser: rfc3164.NewParser(
			rfc3164.WithBestEffort(),
			rfc3164.WithTimezone(time.UTC),
			rfc3164.WithYear(rfc3164.CurrentYear{}),
			rfc3164.WithRFC3339(),
		),
	}
}

var _ parsers.LogParser = (*RFC3164Parser)(nil)

// Parse returns the parsed events or nil if parsing failed
func (p *RFC3164Parser) Parse(log string) ([]*parsers.PantherLog, error) {
	if p.parser == nil {
		return nil, errors.New("nil parser")
	}
	msg, err := p.parser.Parse([]byte(log))
	if err != nil {
		return nil, err
	}
	internalRFC3164 := msg.(*rfc3164.SyslogMessage)

	externalRFC3164 := &RFC3164{
		Priority:  internalRFC3164.Priority,
		Facility:  internalRFC3164.Facility,
		Severity:  internalRFC3164.Severity,
		Timestamp: (*timestamp.RFC3339)(internalRFC3164.Timestamp),
		Hostname:  internalRFC3164.Hostname,
		Appname:   internalRFC3164.Appname,
		ProcID:    internalRFC3164.ProcID,
		MsgID:     internalRFC3164.MsgID,
		Message:   internalRFC3164.Message,
	}

	externalRFC3164.updatePantherFields(p)

	if err := parsers.Validator.Struct(externalRFC3164); err != nil {
		return nil, err
	}

	return externalRFC3164.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *RFC3164Parser) LogType() string {
	return TypeRFC3164
}

func (event *RFC3164) updatePantherFields(p *RFC3164Parser) {
	event.SetCoreFields(p.LogType(), event.Timestamp, event)

	// The hostname should be a FQDN, but may also be an IP address. Check for IP, otherwise
	// add as a domain name. https://tools.ietf.org/html/rfc3164#section-6.2.4
	if !event.AppendAnyIPAddressPtr(event.Hostname) {
		event.AppendAnyDomainNamePtrs(event.Hostname)
	}

	event.AppendAnyIPAddressInFieldPtr(event.Message)
}
