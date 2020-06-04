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
	"github.com/influxdata/go-syslog/v3"
	"github.com/influxdata/go-syslog/v3/rfc5424"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

// nolint:lll
type RFC5424 struct {
	Priority       *uint8                        `json:"priority" validate:"required" description:"Priority is calculated by (Facility * 8 + Severity). The lower this value, the higher importance of the log message."`
	Facility       *uint8                        `json:"facility" validate:"required" description:"Facility value helps determine which process created the message. Eg: 0 = kernel messages, 3 = system daemons."`
	Severity       *uint8                        `json:"severity" validate:"required" description:"Severity indicates how severe the message is. Eg: 0=Emergency to 7=Debug."`
	Version        *uint16                       `json:"version" validate:"required" description:"Version of the syslog message protocol. RFC5424 mandates that version cannot be 0, so a 0 value signals no version."`
	Timestamp      *timestamp.RFC3339            `json:"timestamp,omitempty" description:"Timestamp of the syslog message in UTC."`
	Hostname       *string                       `json:"hostname,omitempty" description:"Hostname identifies the machine that originally sent the syslog message."`
	Appname        *string                       `json:"appname,omitempty" description:"Appname identifies the device or application that originated the syslog message."`
	ProcID         *string                       `json:"procid,omitempty" description:"ProcID is often the process ID, but can be any value used to enable log analyzers to detect discontinuities in syslog reporting."`
	MsgID          *string                       `json:"msgid,omitempty" description:"MsgID identifies the type of message. For example, a firewall might use the MsgID 'TCPIN' for incoming TCP traffic."`
	StructuredData *map[string]map[string]string `json:"structured_data,omitempty" description:"StructuredData provides a mechanism to express information in a well defined and easily parsable format."`
	Message        *string                       `json:"message,omitempty" description:"Message contains free-form text that provides information about the event."`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// RFC5424Parser parses Syslog logs in the RFC5424 format
type RFC5424Parser struct {
	parser syslog.Machine
}

var _ parsers.LogParser = (*RFC5424Parser)(nil)

// New returns an initialized LogParser for Syslog RFC5424 logs
func (p *RFC5424Parser) New() parsers.LogParser {
	return &RFC5424Parser{
		parser: rfc5424.NewParser(rfc5424.WithBestEffort()),
	}
}

// Parse returns the parsed events or nil if parsing failed
func (p *RFC5424Parser) Parse(log string) ([]*parsers.PantherLog, error) {
	if p.parser == nil {
		return nil, errors.New("parser can not be nil")
	}
	msg, err := p.parser.Parse([]byte(log))
	if err != nil {
		return nil, err
	}
	internalRFC5424 := msg.(*rfc5424.SyslogMessage)

	externalRFC5424 := &RFC5424{
		Priority:       internalRFC5424.Priority,
		Facility:       internalRFC5424.Facility,
		Severity:       internalRFC5424.Severity,
		Version:        &internalRFC5424.Version,
		Timestamp:      (*timestamp.RFC3339)(internalRFC5424.Timestamp),
		Hostname:       internalRFC5424.Hostname,
		Appname:        internalRFC5424.Appname,
		ProcID:         internalRFC5424.ProcID,
		MsgID:          internalRFC5424.MsgID,
		StructuredData: internalRFC5424.StructuredData,
		Message:        internalRFC5424.Message,
	}

	externalRFC5424.updatePantherFields(p)

	if err := parsers.Validator.Struct(externalRFC5424); err != nil {
		return nil, err
	}

	return externalRFC5424.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *RFC5424Parser) LogType() string {
	return TypeRFC5424
}

func (event *RFC5424) updatePantherFields(p *RFC5424Parser) {
	event.SetCoreFields(p.LogType(), event.Timestamp, event)

	// The hostname should be a FQDN, but may also be an IP address. Check for IP, otherwise
	// add as a domain name. https://tools.ietf.org/html/rfc5424#section-6.2.4
	if !event.AppendAnyIPAddressPtr(event.Hostname) {
		event.AppendAnyDomainNamePtrs(event.Hostname)
	}

	event.AppendAnyIPAddressInFieldPtr(event.Message)
}
