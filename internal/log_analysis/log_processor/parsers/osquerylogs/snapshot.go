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

const TypeSnapshot = "Osquery.Snapshot"

var LogTypeSnapshot = parsers.LogType{
	Name: TypeSnapshot,
	Description: `Snapshot contains all the data included in OsQuery differential logs
Reference: https://osquery.readthedocs.io/en/stable/deployment/logging/`,
	Schema: struct {
		Snapshot
		logs.Meta
	}{},
	NewParser: NewSnapshotParser,
}

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
}

var _ parsers.PantherEventer = (*Snapshot)(nil)

// SnapshotParser parses OsQuery snapshot logs
type SnapshotParser struct{}

var _ parsers.Interface = (*SnapshotParser)(nil)

func NewSnapshotParser() parsers.Interface {
	return &SnapshotParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *SnapshotParser) Parse(log string) ([]*parsers.Result, error) {
	return parsers.QuickParseJSON(&Snapshot{}, log)
}

func (event *Snapshot) PantherEvent() *logs.Event {
	return logs.NewEvent(TypeSnapshot, event.CalendarTime.UTC(),
		logs.DomainNameP((event.HostIdentifier)),
	)
}
