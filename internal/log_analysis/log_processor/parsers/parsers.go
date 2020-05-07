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
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/jsontricks"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/logs"
)

// Interface represents a parser for a supported log type
// It is designed to act as a 'black box' concerning how the log entry is processed
type Interface interface {
	// Parse attempts to parse the provided log line
	// If the provided log is not of the supported type the method returns nil and an error
	Parse(log string) ([]*Result, error)
}

// Result is the parsed result from a log parser.
// It contains all info required to store a log event in a bucket.
// JSON serialization is a responsibility of the parser. This is a conscious choice
// since there is a lot of (yet untapped) room for performance optimization in the
// process of mapping input to JSON. Having parsers be responsible for this allows
// experimentation in an isolated scope.
type Result struct {
	LogType   string
	EventTime time.Time
	JSON      []byte
}

// Results wraps a single result to a slice of results
func (r *Result) Results() []*Result {
	if r == nil {
		return nil
	}
	return []*Result{r}
}

// PantherEventer is the interface to be implemented by all parsed log events.
// Implementations should use `logs.NewEvent` to get an event from the pool.
type PantherEventer interface {
	PantherEvent() *logs.Event
}

var valid = validator.New()

// QuickParseJSON is a helper method for parsers that produce a single event from each JSON log line input.
func QuickParseJSON(event PantherEventer, src string) ([]*Result, error) {
	if err := jsoniter.UnmarshalFromString(src, event); err != nil {
		return nil, err
	}
	if err := valid.Struct(event); err != nil {
		return nil, err
	}
	result, err := PackResult(event)
	if err != nil {
		return nil, err
	}
	return result.Results(), nil
}

// PackResults is a helper function for parsers to convert log events to PantherLogJSON.
// It validates, composes and serializes an appropriate struct based on the PantherEvent returned by the arguments.
func PackResults(events ...PantherEventer) ([]*Result, error) {
	results := make([]*Result, 0, len(events))
	for _, event := range events {
		if event == nil {
			continue
		}

		result, err := PackResult(event)
		if err != nil {
			return nil, errors.Errorf("Failed to pack event: %s", err)
		}
		results = append(results, result)
	}
	return results, nil
}

// PackResult is a helper function for parsers to convert a log event to Result.
// It detects the appropriate base pantherlog Meta struct to used from the prefix of the LogType.
// Custom panther logs that handle 'exotic' panther fields such as AWSPantherLog need to be
// registered in an `init()` block with `pantherlog.RegisterPrefix`
func PackResult(e PantherEventer) (*Result, error) {
	if e == nil {
		return nil, errors.Errorf("nil event")
	}

	event := e.PantherEvent()
	// Nil event is considered an error
	if event == nil {
		return nil, errors.Errorf("nil event")
	}

	// Meta uses logs.MetaFactory that should handle validate meta validation.
	meta, err := event.Meta()
	if err != nil {
		event.Close()
		return nil, err
	}

	// Compose a JSON object of fields of meta and e
	// Order is important
	resultJSON, err := jsontricks.ConcatObjects(nil, e, meta)
	if err != nil {
		event.Close()
		return nil, err
	}

	event.Close()
	return &Result{
		LogType:   event.LogType,
		EventTime: event.Timestamp,
		JSON:      resultJSON,
	}, nil
}
