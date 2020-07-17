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
	"io"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/rowid"
)

// LogParser represents a parser for a supported log type
// NOTE: We will be transitioning parsers to the `pantherlog.LogParser` interface.
// Until all parsers are converted to the new interface the `AdapterFactory()` helper should be used
// when registering a `logtypes.Entry` that uses this interface.
type LogParser interface {
	// LogType returns the log type supported by this parser
	LogType() string

	// Parse attempts to parse the provided log line
	// If the provided log is not of the supported type the method returns nil and an error
	Parse(log string) ([]*PantherLog, error)

	// New returns a new instance of the log parser, used like a factory method for stateful parsers
	New() LogParser
}

// Validator can be used to validate schemas of log fields
var Validator = NewValidator()

func NewValidator() *validator.Validate {
	v := validator.New()
	null.RegisterValidators(v)
	return v
}

// JSON is a custom jsoniter config to properly remap field names for compatibility with Athena views
var JSON = pantherlog.JSON()

// Interface is the interface to be used for log parsers.
type Interface interface {
	ParseLog(log string) ([]*Result, error)
}

// Result is the result of parsing a log event.
// It contains the JSON form of the pantherlog to be stored for queries.
type Result = pantherlog.Result

// Factory creates new parser instances.
// The params argument defines parameters for a parser.
type Factory interface {
	NewParser(params interface{}) (Interface, error)
}

type FactoryFunc func(params interface{}) (Interface, error)

func (ff FactoryFunc) NewParser(params interface{}) (Interface, error) {
	return ff(params)
}

// AdapterFactory returns a pantherlog.LogParser factory from a parsers.Parser
// This is used to ease transition to the new pantherlog.EventTypeEntry registry.
func AdapterFactory(parser LogParser) Factory {
	return FactoryFunc(func(_ interface{}) (Interface, error) {
		return NewAdapter(parser), nil
	})
}

// NewAdapter creates a pantherlog.LogParser from a parsers.Parser
func NewAdapter(parser LogParser) Interface {
	return &logParserAdapter{
		LogParser: parser.New(),
	}
}

type logParserAdapter struct {
	LogParser
}

func (a *logParserAdapter) ParseLog(log string) ([]*Result, error) {
	return ToResults(a.LogParser.Parse(log))
}

type SimpleJSONParserFactory struct {
	NewEvent       func() pantherlog.Event
	JSON           jsoniter.API
	Validate       func(event interface{}) error
	ResultBuilder  *pantherlog.ResultBuilder
	ReadBufferSize int
}

type simpleJSONEventParser struct {
	newEvent  func() pantherlog.Event
	iter      *jsoniter.Iterator
	validate  func(x interface{}) error
	builder   *pantherlog.ResultBuilder
	logReader io.Reader
}

func (p *simpleJSONEventParser) ParseLog(log string) ([]*Result, error) {
	event := p.newEvent()
	p.logReader.(*strings.Reader).Reset(log)
	p.iter.Reset(p.logReader)
	p.iter.ReadVal(event)
	if err := p.iter.Error; err != nil {
		return nil, err
	}
	if err := p.validate(event); err != nil {
		return nil, err
	}
	result, err := p.builder.BuildResult(event)
	if err != nil {
		return nil, err
	}
	return []*Result{result}, nil
}

func (f *SimpleJSONParserFactory) NewParser(_ interface{}) (Interface, error) {
	api := f.JSON
	if api == nil {
		api = jsoniter.ConfigDefault
	}
	validate := f.Validate
	if validate == nil {
		validate = pantherlog.ValidateStruct
	}

	builder := f.ResultBuilder
	if builder == nil {
		builder = &pantherlog.ResultBuilder{
			Meta:      pantherlog.DefaultMetaFields(),
			NextRowID: rowid.Next,
			Now:       time.Now,
		}
	}
	const minBufferSize = 512
	bufferSize := f.ReadBufferSize
	if bufferSize < minBufferSize {
		bufferSize = minBufferSize
	}

	iter := jsoniter.Parse(api, nil, bufferSize)
	return &simpleJSONEventParser{
		newEvent:  f.NewEvent,
		iter:      iter,
		validate:  validate,
		builder:   builder,
		logReader: strings.NewReader(`null`),
	}, nil
}
