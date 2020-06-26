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
type Snapshot struct { // FIXME: field descriptions need updating!
	Action         *string                `json:"action,omitempty" validate:"required,eq=snapshot" description:"Action"`
	CalendarTime   *timestamp.ANSICwithTZ `json:"calendarTime,omitempty" validate:"required" description:"The time of the event (UTC)."`
	Counter        *numerics.Integer      `json:"counter,omitempty" validate:"required" description:"Counter"`
	Decorations    map[string]string      `json:"decorations,omitempty" description:"Decorations"`
	Epoch          *numerics.Integer      `json:"epoch,omitempty" validate:"required" description:"Epoch"`
	HostIdentifier *string                `json:"hostIdentifier,omitempty" validate:"required" description:"HostIdentifier"`
	Name           *string                `json:"name,omitempty" validate:"required" description:"Name"`
	Snapshot       []map[string]string    `json:"snapshot,omitempty" validate:"required" description:"Snapshot"`
	UnixTime       *numerics.Integer      `json:"unixTime,omitempty" validate:"required" description:"UnixTime"`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// SnapshotParser parses OsQuery snapshot logs
type SnapshotParser struct{}

var _ parsers.LogParser = (*SnapshotParser)(nil)

func (p *SnapshotParser) New() parsers.LogParser {
	return &SnapshotParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *SnapshotParser) Parse(log string) ([]*parsers.PantherLog, error) {
	event := &Snapshot{}
	err := jsoniter.UnmarshalFromString(log, event)
	if err != nil {
		return nil, err
	}

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		return nil, err
	}
	return event.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *SnapshotParser) LogType() string {
	return TypeSnapshot
}

func (event *Snapshot) updatePantherFields(p *SnapshotParser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.CalendarTime), event)
	event.AppendAnyDomainNamePtrs(event.HostIdentifier)
}
