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

var RFC3164Desc = `Fluentd syslog parser for the RFC3164 format (ie. BSD-syslog messages)
Reference: https://docs.fluentd.org/parser/syslog#rfc3164-log`

// nolint:lll
type RFC3164 struct {
	Priority  *uint8                      `json:"pri" description:"Priority is calculated by (Facility * 8 + Severity). The lower this value, the higher importance of the log message."`
	Hostname  *string                     `json:"host,omitempty" validate:"required" description:"Hostname identifies the machine that originally sent the syslog message."`
	Ident     *string                     `json:"ident,omitempty" validate:"required" description:"Appname identifies the device or application that originated the syslog message."`
	ProcID    *numerics.Integer           `json:"pid,omitempty" description:"ProcID is often the process ID, but can be any value used to enable log analyzers to detect discontinuities in syslog reporting."`
	Message   *string                     `json:"message,omitempty" validate:"required" description:"Message contains free-form text that provides information about the event."`
	Timestamp *timestamp.FluentdTimestamp `json:"time,omitempty" validate:"required" description:"Timestamp of the syslog message in UTC."`
	Tag       *string                     `json:"tag,omitempty" validate:"required" description:"Tag of the syslog message"`
	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// RFC3164Parser parses Fluentd syslog logs in the RFC3164 format
type RFC3164Parser struct{}

var _ parsers.LogParser = (*RFC3164Parser)(nil)

func (p *RFC3164Parser) New() parsers.LogParser {
	return &RFC3164Parser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *RFC3164Parser) Parse(log string) ([]*parsers.PantherLog, error) {
	rfc3164 := &RFC3164{}

	err := jsoniter.UnmarshalFromString(log, rfc3164)
	if err != nil {
		return nil, err
	}

	rfc3164.updatePantherFields(p)

	if err := parsers.Validator.Struct(rfc3164); err != nil {
		return nil, err
	}

	return rfc3164.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *RFC3164Parser) LogType() string {
	return "Fluentd.Syslog3164"
}

func (event *RFC3164) updatePantherFields(p *RFC3164Parser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.Timestamp), event)

	// The hostname should be a FQDN, but may also be an IP address. Check for IP, otherwise
	// add as a domain name. https://tools.ietf.org/html/rfc3164#section-6.2.4
	if !event.AppendAnyIPAddressPtr(event.Hostname) {
		event.AppendAnyDomainNamePtrs(event.Hostname)
	}

	event.AppendAnyIPAddressInFieldPtr(event.Message)
}
