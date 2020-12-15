// Package customparser provides a log parser that uses reflection
package customparser

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
	"reflect"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/preprocessors"
)

// Factory implements parsers.Factory interface using reflection to parse json log entries to a single log event.
type Factory struct {
	LogType      string
	EventSchema  reflect.Type
	PreProcessor preprocessors.Interface
	API          jsoniter.API
	Builder      pantherlog.ResultBuilder
	Validate     func(interface{}) error
}

// NewParser implements parsers.Factory interface.
// Since the parser accepts no parameters we use _ as the params argument name.
func (f *Factory) NewParser(_ interface{}) (pantherlog.LogParser, error) {
	decoder := newEventDecoderJSON(f.API, f.EventSchema)
	builder := f.Builder
	return preprocessors.Wrap(&parser{
		logType:       f.LogType,
		eventDecoder:  decoder,
		validate:      f.Validate,
		resultBuilder: &builder,
	}, f.PreProcessor), nil
}

type eventDecoderJSON struct {
	schema    reflect.Type
	logReader *strings.Reader
	iter      *jsoniter.Iterator
}

func newEventDecoderJSON(api jsoniter.API, schema reflect.Type) *eventDecoderJSON {
	const bufferSize = 8192
	r := strings.NewReader(`null`)
	iter := jsoniter.Parse(api, r, bufferSize)
	return &eventDecoderJSON{
		schema:    schema,
		logReader: r,
		iter:      iter,
	}
}

func (d *eventDecoderJSON) DecodeEvent(log string) (event interface{}, err error) {
	// Reset the iterator to read from log
	d.logReader.Reset(log)
	d.iter.Reset(d.logReader)
	val := reflect.New(d.schema)
	event = val.Interface()
	d.iter.ReadVal(event)
	err, d.iter.Error = d.iter.Error, nil
	if err != nil {
		return
	}
	return
}

// Parser implements parsers.Interface.
type parser struct {
	logType       string
	eventDecoder  *eventDecoderJSON
	validate      func(interface{}) error
	resultBuilder *pantherlog.ResultBuilder
}

// Parse implements parsers.Interface
func (p *parser) ParseLog(log string) ([]*pantherlog.Result, error) {
	if log == "" {
		return nil, nil
	}
	event, err := p.eventDecoder.DecodeEvent(log)
	if err != nil {
		return nil, errors.Wrapf(err, "parse failed")
	}
	if err := p.validate(event); err != nil {
		return nil, errors.Wrapf(err, "validate failed")
	}
	result, err := p.resultBuilder.BuildResult(p.logType, event)
	if err != nil {
		return nil, errors.Wrapf(err, "result failed")
	}
	return []*pantherlog.Result{result}, nil
}
