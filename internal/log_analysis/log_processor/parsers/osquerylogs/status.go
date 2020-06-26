package osquerylogs

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
type Status struct { // FIXME: field descriptions need updating!
	CalendarTime      *timestamp.ANSICwithTZ `json:"calendarTime,omitempty" validate:"required" description:"The time of the event (UTC)."`
	Decorations       map[string]string      `json:"decorations,omitempty" description:"Decorations"`
	Filename          *string                `json:"filename,omitempty" validate:"required" description:"Filename"`
	HostIdentifier    *string                `json:"hostIdentifier,omitempty" validate:"required" description:"HostIdentifier"`
	Line              *numerics.Integer      `json:"line,omitempty" validate:"required" description:"Line"`
	LogType           *string                `json:"logType,omitempty"  description:"LogType"`
	LogUnderscoreType *string                `json:"log_type,omitempty" description:"LogUnderScoreType"`
	Message           *string                `json:"message,omitempty" description:"Message"`
	Severity          *numerics.Integer      `json:"severity,omitempty" validate:"required" description:"Severity"`
	UnixTime          *numerics.Integer      `json:"unixTime,omitempty" validate:"required" description:"UnixTime"`
	Version           *string                `json:"version,omitempty" validate:"required" description:"Version"`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// StatusParser parses OsQuery Status logs
type StatusParser struct{}

var _ parsers.LogParser = (*StatusParser)(nil)

func (p *StatusParser) New() parsers.LogParser {
	return &StatusParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *StatusParser) Parse(log string) ([]*parsers.PantherLog, error) {
	event := &Status{}
	err := jsoniter.UnmarshalFromString(log, event)
	if err != nil {
		return nil, err
	}

	// Populating LogType with LogTypeInput value
	// This is needed because we want the JSON field with key `log_type` to be marshalled
	// with key `logtype`
	event.LogType = event.LogUnderscoreType
	event.LogUnderscoreType = nil

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		return nil, err
	}
	return event.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *StatusParser) LogType() string {
	return TypeStatus
}

func (event *Status) updatePantherFields(p *StatusParser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.CalendarTime), event)
	event.AppendAnyDomainNamePtrs(event.HostIdentifier)
}
