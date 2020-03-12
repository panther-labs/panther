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

var DifferentialDesc = `Differential contains all the data included in OsQuery differential logs
Reference: https://osquery.readthedocs.io/en/stable/deployment/logging/`

// nolint:lll
type Differential struct { // FIXME: field descriptions need updating!
	Action               *string                `json:"action,omitempty" validate:"required" description:"Action"`
	CalendarTime         *timestamp.ANSICwithTZ `json:"calendartime,omitempty" validate:"required" description:"The time of the event (UTC)."`
	Columns              map[string]string      `json:"columns,omitempty" validate:"required" description:"Columns"`
	Counter              *int                   `json:"counter,omitempty,string" description:"Counter"`
	Decorations          map[string]string      `json:"decorations,omitempty" description:"Decorations"`
	Epoch                *int                   `json:"epoch,omitempty,string" validate:"required" description:"Epoch"`
	HostIdentifier       *string                `json:"hostIdentifier,omitempty" validate:"required" description:"HostIdentifier"`
	LogType              *string                `json:"logType,omitempty" validate:"required,eq=result" description:"LogType"`
	LogUnderscoreType    *string                `json:"log_type,omitempty" description:"LogUnderscoreType"`
	Name                 *string                `json:"name,omitempty" validate:"required" description:"Name"`
	UnixTime             *int                   `json:"unixTime,omitempty,string" validate:"required" description:"UnixTime"`
	LogNumericsAsNumbers *bool                  `json:"logNumericsAsNumbers,omitempty,string" description:"LogNumericsAsNumbers"`

	// NOTE: added to end of struct to allow expansion later
	parsers.PantherLog
}

// DifferentialParser parses OsQuery Differential logs
type DifferentialParser struct{}

func (p *DifferentialParser) New() parsers.LogParser {
	return &DifferentialParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *DifferentialParser) Parse(log string) []*parsers.PantherLog {
	event := &Differential{}
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
func (p *DifferentialParser) LogType() string {
	return "Osquery.Differential"
}

func (event *Differential) updatePantherFields(p *DifferentialParser) {
	event.SetCoreFields(p.LogType(), (*timestamp.RFC3339)(event.CalendarTime), event)
	event.AppendAnyDomainNamePtrs(event.HostIdentifier)
}
