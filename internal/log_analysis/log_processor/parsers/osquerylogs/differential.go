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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeDifferential = "Osquery.Differential"

var DifferentialDesc = `Differential contains all the data included in OsQuery differential logs
Reference: https://osquery.readthedocs.io/en/stable/deployment/logging/`

// nolint:lll
type Differential struct { // FIXME: field descriptions need updating!
	Action         *string                `json:"action,omitempty" validate:"required" description:"Action"`
	CalendarTime   *timestamp.ANSICwithTZ `json:"calendarTime,omitempty" validate:"required" description:"The time of the event (UTC)."`
	Columns        map[string]string      `json:"columns,omitempty" validate:"required" description:"Columns"`
	Counter        *numerics.Integer      `json:"counter,omitempty" description:"Counter"`
	Decorations    map[string]string      `json:"decorations,omitempty" description:"Decorations"`
	Epoch          *numerics.Integer      `json:"epoch,omitempty" validate:"required" description:"Epoch"`
	HostIdentifier *string                `json:"hostIdentifier,omitempty" validate:"required" description:"HostIdentifier"`
	LogType        *string                `json:"log_type,omitempty"  description:"LogType"`
	// LogUnderscoreType    *string           `json:"log_type,omitempty" description:"LogUnderscoreType"`
	Name                 *string           `json:"name,omitempty" validate:"required" description:"Name"`
	UnixTime             *numerics.Integer `json:"unixTime,omitempty" validate:"required" description:"UnixTime"`
	LogNumericsAsNumbers *bool             `json:"logNumericsAsNumbers,omitempty,string" description:"LogNumericsAsNumbers"`
}

var _ parsers.PantherEventer = (*Differential)(nil)

// DifferentialParser parses OsQuery Differential logs
type DifferentialParser struct{}

var _ parsers.Parser = (*DifferentialParser)(nil)

func (p *DifferentialParser) New() parsers.Parser {
	return &DifferentialParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *DifferentialParser) Parse(log string) ([]*parsers.PantherLogJSON, error) {
	return parsers.QuickParseJSON(&Differential{}, log)
	// Populating LogType with LogTypeInput value
	// This is needed because we want the JSON field with key `log_type` to be marshalled
	// with key `logtype`
	// event.LogType = event.LogUnderscoreType
	// event.LogUnderscoreType = nil
}

// LogType returns the log type supported by this parser
func (p *DifferentialParser) LogType() string {
	return TypeDifferential
}

func (event *Differential) PantherEvent() *parsers.PantherEvent {
	return parsers.NewEvent(TypeDifferential, event.CalendarTime.UTC(),
		parsers.DomainNameP(event.HostIdentifier),
		parsers.IPAddress(event.Columns["local_address"]),
		parsers.IPAddress(event.Columns["remote_address"]),
	)
}
