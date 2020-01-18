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
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var BatchDesc = `Batch contains all the data included in OsQuery batch logs
Reference : https://osquery.readthedocs.io/en/stable/deployment/logging/`

type Batch struct {
	CalendarTime *timestamp.ANSICwithTZ `json:"calendarTime,omitempty" validate:"required"`
	Counter      *int                   `json:"counter,omitempty,string"  validate:"required"`
	Decorations  map[string]string      `json:"decorations,omitempty"`
	DiffResults  *BatchDiffResults      `json:"diffResults,omitempty" validate:"required"`
	Epoch        *int                   `json:"epoch,omitempty,string"  validate:"required"`
	Hostname     *string                `json:"hostname,omitempty"  validate:"required"`
	Name         *string                `json:"name,omitempty"  validate:"required"`
	UnixTime     *int                   `json:"unixTime,omitempty,string"  validate:"required"`
}

// OsqueryBatchDiffResults contains diff data for OsQuery batch results
type BatchDiffResults struct {
	Added   []map[string]string `json:"added,omitempty"`
	Removed []map[string]string `json:"removed,omitempty"`
}

// BatchParser parses OsQuery Batch logs
type BatchParser struct{}

// Parse returns the parsed events or nil if parsing failed
func (p *BatchParser) Parse(log string) []interface{} {
	event := &Batch{}
	err := jsoniter.UnmarshalFromString(log, event)
	if err != nil {
		zap.L().Debug("failed to unmarshal log", zap.Error(err))
		return nil
	}

	tsa, _ := jsoniter.MarshalToString(event)
	fmt.Println(tsa)

	if err := parsers.Validator.Struct(event); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}
	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *BatchParser) LogType() string {
	return "Osquery.Batch"
}
