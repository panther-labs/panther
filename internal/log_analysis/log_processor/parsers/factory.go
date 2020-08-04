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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

// Factory creates new parser instances.
// The params argument defines parameters for a parser.
type Factory interface {
	NewParser(params interface{}) (Interface, error)
}

// FactoryFunc is a callback parser factory
type FactoryFunc func(params interface{}) (Interface, error)

// NewParser implements Factory interface
func (ff FactoryFunc) NewParser(params interface{}) (Interface, error) {
	return ff(params)
}

// AdapterFactory returns a parsers.Factory from a parsers.Parser
// This is used to ease transition to the new parsers.Interface for parsers based on parsers.PantherLog
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
	results, err := a.LogParser.Parse(log)
	if err != nil {
		return nil, err
	}
	return ToResults(results, nil)
}

type JSONParserFactory struct {
	LogType        string
	NewEvent       func() interface{}
	JSON           jsoniter.API
	Validate       func(event interface{}) error
	ReadBufferSize int
	NextRowID      func() string
	Now            func() time.Time
	Meta           []pantherlog.FieldID
}

func (f *JSONParserFactory) NewParser(_ interface{}) (Interface, error) {
	validate := f.Validate
	if validate == nil {
		validate = ValidateStruct
	}

	logReader := strings.NewReader(`null`)

	const minBufferSize = 512
	bufferSize := f.ReadBufferSize
	if bufferSize < minBufferSize {
		bufferSize = minBufferSize
	}
	api := f.JSON
	if api == nil {
		api = common.BuildJSON()
	}
	iter := jsoniter.Parse(api, logReader, bufferSize)

	return &simpleJSONParser{
		newEvent: f.NewEvent,
		iter:     iter,
		validate: validate,
		builder: pantherlog.ResultBuilder{
			LogType:   f.LogType,
			Meta:      f.Meta,
			Now:       f.Now,
			NextRowID: f.NextRowID,
		},
		logReader: logReader,
	}, nil
}

var validate = func() *validator.Validate {
	v := validator.New()
	null.RegisterValidators(v)
	return v
}()

func ValidateStruct(s interface{}) error {
	return validate.Struct(s)
}

type simpleJSONParser struct {
	newEvent  func() interface{}
	iter      *jsoniter.Iterator
	validate  func(x interface{}) error
	builder   pantherlog.ResultBuilder
	logReader io.Reader
}

func (p *simpleJSONParser) ParseLog(log string) ([]*Result, error) {
	event := p.newEvent()
	p.logReader.(*strings.Reader).Reset(log)
	p.iter.Reset(p.logReader)
	p.iter.Error = nil
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
