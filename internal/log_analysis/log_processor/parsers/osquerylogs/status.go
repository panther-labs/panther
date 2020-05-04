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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/logs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeStatus = "Osquery.Status"

var LogTypeStatus = parsers.LogType{
	Name: TypeStatus,
	Description: `Status is a diagnostic osquery log about the daemon.
Reference: https://osquery.readthedocs.io/en/stable/deployment/logging/`,
	NewParser: NewStatusParser,
	Schema: struct {
		Status
		logs.Meta
	}{},
}

// nolint:lll
type Status struct { // FIXME: field descriptions need updating!
	CalendarTime   *timestamp.ANSICwithTZ `json:"calendarTime,omitempty" validate:"required" description:"The time of the event (UTC)."`
	Decorations    map[string]string      `json:"decorations,omitempty" description:"Decorations"`
	Filename       *string                `json:"filename,omitempty" validate:"required" description:"Filename"`
	HostIdentifier *string                `json:"hostIdentifier,omitempty" validate:"required" description:"HostIdentifier"`
	Line           *numerics.Integer      `json:"line,omitempty" validate:"required" description:"Line"`
	LogType        *string                `json:"log_type,omitempty"  description:"LogType"`
	// LogUnderscoreType *string                `json:"log_type,omitempty" description:"LogUnderScoreType"`
	Message  *string           `json:"message,omitempty" description:"Message"`
	Severity *numerics.Integer `json:"severity,omitempty" validate:"required" description:"Severity"`
	UnixTime *numerics.Integer `json:"unixTime,omitempty" validate:"required" description:"UnixTime"`
	Version  *string           `json:"version,omitempty" validate:"required" description:"Version"`
}

var _ parsers.PantherEventer = (*Status)(nil)

// StatusParser parses OsQuery Status logs
type StatusParser struct{}

var _ parsers.Interface = (*StatusParser)(nil)

func NewStatusParser() parsers.Interface {
	return &StatusParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *StatusParser) Parse(log string) ([]*parsers.Result, error) {
	return parsers.QuickParseJSON(&Status{}, log)
	// event := &Status{}
	// err := jsoniter.UnmarshalFromString(log, event)
	// if err != nil {
	// 	return nil, err
	// }

	// // Populating LogType with LogTypeInput value
	// // This is needed because we want the JSON field with key `log_type` to be marshalled
	// // with key `logtype`
	// event.LogType = event.LogUnderscoreType
	// event.LogUnderscoreType = nil

	// event.updatePantherFields(p)

	// if err := parsers.Validator.Struct(event); err != nil {
	// 	return nil, err
	// }
	// return event.Logs(), nil
}

func (event *Status) PantherEvent() *logs.Event {
	return logs.NewEvent(TypeStatus, event.CalendarTime.UTC(),
		logs.DomainNameP(event.HostIdentifier),
	)
}
