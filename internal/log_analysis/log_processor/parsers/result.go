package parsers

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
	"errors"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common/logs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/jsontricks"
)

type Interface interface {
	ParseLog(log string) ([]*Result, error)
}

type Result struct {
	LogType   string
	EventTime time.Time
	JSON      []byte
}

func (r *Result) Results() []*Result {
	if r == nil {
		return nil
	}
	return []*Result{r}
}

type PantherLogEventer interface {
	PantherLogEvent() *logs.Event
}

func PackResult(logEvent PantherLogEventer) (*Result, error) {
	if logEvent == nil {
		return nil, errors.New("nil log")
	}

	event := logEvent.PantherLogEvent()
	if event == nil {
		return nil, errors.New("nil event")
	}
	meta, err := event.Meta()
	if err != nil {
		return nil, err
	}
	data, err := jsontricks.ConcatObjects(JSON, nil, logEvent, meta)
	if err != nil {
		return nil, err
	}

	return &Result{
		LogType:   event.LogType,
		EventTime: event.Timestamp,
		JSON:      data,
	}, nil
}

func QuickParseJSON(log string, logEvent PantherLogEventer) ([]*Result, error) {
	if err := jsoniter.UnmarshalFromString(log, logEvent); err != nil {
		return nil, err
	}
	if err := Validator.Struct(logEvent); err != nil {
		return nil, err
	}
	event := logEvent.PantherLogEvent()
	if event == nil {
		return nil, errors.New("nil event")
	}
	meta, err := event.Meta()
	if err != nil {
		event.Close()
		return nil, err
	}

	data, err := jsontricks.ConcatObjects(JSON, nil, logEvent, meta)
	if err != nil {
		event.Close()
		return nil, err
	}
	result := Result{
		LogType:   event.LogType,
		EventTime: event.Timestamp,
		JSON:      data,
	}
	event.Close()
	return result.Results(), nil
}

// Result converts a PantherLog to Result
// NOTE: Currently in this file to help with review
func (pl *PantherLog) Result() (*Result, error) {
	event := pl.Event()
	if event == nil {
		return nil, errors.New("nil event")
	}
	if pl.PantherLogType == nil {
		return nil, errors.New("nil log type")
	}
	if pl.PantherEventTime == nil {
		return nil, errors.New("nil event time")
	}
	tm := ((*time.Time)(pl.PantherEventTime)).UTC()
	// Use custom JSON marshaler to rewrite fields
	data, err := JSON.Marshal(event)
	if err != nil {
		return nil, err
	}
	return &Result{
		LogType:   *pl.PantherLogType,
		EventTime: tm,
		JSON:      data,
	}, nil
}

// Results converts a PantherLog to a slice of results
// NOTE: Currently in this file to help with review
func (pl *PantherLog) Results() ([]*Result, error) {
	result, err := pl.Result()
	if err != nil {
		return nil, err
	}
	return []*Result{result}, nil
}
