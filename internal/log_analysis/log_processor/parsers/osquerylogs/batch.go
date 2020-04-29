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

const TypeBatch = "Osquery.Batch"

var BatchDesc = `Batch contains all the data included in OsQuery batch logs
Reference : https://osquery.readthedocs.io/en/stable/deployment/logging/`

// nolint:lll
type Batch struct { // FIXME: field descriptions need updating!
	CalendarTime *timestamp.ANSICwithTZ `json:"calendarTime,omitempty" validate:"required" description:"The time of the event (UTC)."`
	Counter      *numerics.Integer      `json:"counter,omitempty"  validate:"required" description:"Counter"`
	Decorations  map[string]string      `json:"decorations,omitempty" description:"Decorations"`
	DiffResults  *BatchDiffResults      `json:"diffResults,omitempty" validate:"required" description:"Computed differences."`
	Epoch        *numerics.Integer      `json:"epoch,omitempty"  validate:"required" description:"Epoch"`
	Hostname     *string                `json:"hostname,omitempty"  validate:"required" description:"Hostname"`
	Name         *string                `json:"name,omitempty"  validate:"required" description:"Name"`
	UnixTime     *numerics.Integer      `json:"unixTime,omitempty"  validate:"required" description:"Unix epoch"`
}

var _ parsers.PantherEventer = (*Batch)(nil)

// OsqueryBatchDiffResults contains diff data for OsQuery batch results
type BatchDiffResults struct {
	Added   []map[string]string `json:"added,omitempty"`
	Removed []map[string]string `json:"removed,omitempty"`
}

// BatchParser parses OsQuery Batch logs
type BatchParser struct{}

var _ parsers.Parser = (*BatchParser)(nil)

func (p *BatchParser) New() parsers.Parser {
	return &BatchParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *BatchParser) Parse(log string) ([]*parsers.PantherLogJSON, error) {
	return parsers.QuickParseJSON(&Batch{}, log)
}

// LogType returns the log type supported by this parser
func (p *BatchParser) LogType() string {
	return TypeBatch
}

func (event *Batch) PantherEvent() *parsers.PantherEvent {
	return parsers.NewEvent(TypeBatch, event.CalendarTime.UTC(),
		parsers.DomainNameP(event.Hostname),
	)
}
