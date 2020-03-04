package osquerylogs

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
	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var StatusDesc = `Status is a diagnostic osquery log about the daemon.
Reference: https://osquery.readthedocs.io/en/stable/deployment/logging/`

// nolint:lll
type Status struct { // FIXME: field descriptions need updating!
	CalendarTime      *timestamp.ANSICwithTZ `json:"calendarTime,omitempty" validate:"required" description:"The time of the event (UTC)."`
	Decorations       map[string]string      `json:"decorations,omitempty" description:"Decorations"`
	Filename          *string                `json:"filename,omitempty" validate:"required" description:"Filename"`
	HostIdentifier    *string                `json:"hostIdentifier,omitempty" validate:"required" description:"HostIdentifier"`
	Line              *int                   `json:"line,omitempty,string" validate:"required" description:"Line"`
	LogType           *string                `json:"logType,omitempty" validate:"required,eq=status" description:"LogType"`
	LogUnderscoreType *string                `json:"log_type,omitempty" description:"LogUnderScoreType"`
	Message           *string                `json:"message,omitempty" description:"Message"`
	Severity          *int                   `json:"severity,omitempty,string" validate:"required" description:"Severity"`
	UnixTime          *int                   `json:"unixTime,omitempty,string" validate:"required" description:"UnixTime"`
	Version           *string                `json:"version,omitempty" validate:"required" description:"Version"`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// StatusParser parses OsQuery Status logs
type StatusParser struct{}

func (p *StatusParser) New() parsers.LogParser {
	return &StatusParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *StatusParser) Parse(log string) []*parsers.PantherLog {
	event := &Status{}
	err := jsoniter.UnmarshalFromString(log, event)
	if err != nil {
		zap.L().Debug("failed to unmarshal log", zap.Error(err))
		return nil
	}

	// Populating LogType with LogTypeInput value
	// This is needed because we want the JSON field with key `log_type` to be marshalled
	// with key `logtype`
	event.LogType = event.LogUnderscoreType
	event.LogUnderscoreType = nil

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}
	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *StatusParser) LogType() string {
	return "Osquery.Status"
}

func (event *Status) updatePantherFields(p *StatusParser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.CalendarTime), event)
	event.AppendAnyDomainNamePtrs(event.HostIdentifier)
}
