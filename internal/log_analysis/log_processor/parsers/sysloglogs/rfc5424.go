package sysloglogs

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"time"

	"go.uber.org/zap"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/influxdata/go-syslog/v3/rfc5424"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var RFC5424Desc = `Syslog parser for the RFC5424 format.
Reference: https://tools.ietf.org/html/rfc5424`

// nolint:lll
type RFC5424 struct {
	Priority       *int16                        `json:"priority" validate:"required" description:"Priority is calculated by (Facility * 8 + Severity). The lower this value, the higher importance of the log message."`
	Facility       *int16                        `json:"facility" validate:"required" description:"Facility value helps determine which process created the message. Eg: 0 = kernel messages, 3 = system daemons."`
	Severity       *int16                        `json:"severity" validate:"required" description:"Severity indicates how severe the message is. Eg: 0=Emergency to 7=Debug."`
	Version        *int16                        `json:"version" validate:"required" description:"Version of the syslog message protocol. RFC5424 mandates that version cannot be 0, so a 0 value signals no version."`
	Timestamp      *timestamp.RFC3339            `json:"timestamp,omitempty" description:"Timestamp of the syslog message."`
	Hostname       *string                       `json:"hostname,omitempty" description:"Hostname identifies the machine that originally sent the syslog message."`
	Appname        *string                       `json:"appname,omitempty" description:"Appname identifies the device or application that originated the syslog message."`
	ProcID         *string                       `json:"procid,omitempty" description:"ProcID is often the process ID, but can be any value used to enable log analyzers to detect discontinuities in syslog reporting."`
	MsgID          *string                       `json:"msgid,omitempty" description:"MsgID identifies the type of message. For example, a firewall might use the MsgID 'TCPIN' for incoming TCP traffic."`
	StructuredData *map[string]map[string]string `json:"structured_data,omitempty" description:"StructuredData provides a mechanism to express information in a well defined and easily parsable format."`
	Message        *string                       `json:"message,omitempty" description:"Message contains free-form text that provides information about the event."`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// RFC5424Parser parses Syslog RFC5424 alerts in the JSON format
type RFC5424Parser struct{}

func (p *RFC5424Parser) New() parsers.LogParser {
	return &RFC5424Parser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *RFC5424Parser) Parse(log string) []interface{} {
	parser := rfc5424.NewParser(rfc5424.WithBestEffort())

	msg, err := parser.Parse([]byte(log))
	if err != nil {
		fmt.Println(err)
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}
	internalRFC5424 := msg.(*rfc5424.SyslogMessage)

	externalRFC5424 := &RFC5424{
		Priority:       aws.Int16(int16(*internalRFC5424.Priority)),
		Facility:       aws.Int16(int16(*internalRFC5424.Facility)),
		Severity:       aws.Int16(int16(*internalRFC5424.Severity)),
		Version:        aws.Int16(int16(internalRFC5424.Version)),
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
		fmt.Println(err)
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return []interface{}{externalRFC5424}
}

// LogType returns the log type supported by this parser
func (p *RFC5424Parser) LogType() string {
	return "Syslog.RFC5424"
}

func (event *RFC5424) updatePantherFields(p *RFC5424Parser) {
	if event.Timestamp != nil {
		event.SetCoreFieldsPtr(p.LogType(), event.Timestamp)
	} else {
		// A null timestamp is valid in RFC5242 (https://tools.ietf.org/html/rfc5424#section-6.2.3).
		// Record the current time instead, and set PantherEventTimeWhenParsed to indicate the reconstructed time.
		event.SetCoreFields(p.LogType(), (timestamp.RFC3339)(time.Now().UTC()))
		event.PantherEventTimeWhenParsed = aws.Bool(true)
	}
}
