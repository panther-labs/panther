package pantherlog

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
	"context"
	"io"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

type LogParserFactory interface {
	NewParser(_ interface{}) (LogParser, error)
}

var _ LogParserFactory = (FactoryFunc)(nil)

type FactoryFunc func(params interface{}) (LogParser, error)

func (f FactoryFunc) NewParser(params interface{}) (LogParser, error) {
	return f(params)
}

type ParserResolver interface {
	ResolveParser(ctx context.Context, name string) (LogParser, error)
}

type LogParser interface {
	ParseLog(log string) ([]*Result, error)
}

type JSONParserFactory struct {
	LogType        string
	NewEvent       func() interface{}
	JSON           jsoniter.API
	Validate       func(event interface{}) error
	ReadBufferSize int
	NextRowID      func() string
	Now            func() time.Time
}

func (f *JSONParserFactory) NewParser(_ interface{}) (LogParser, error) {
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
		api = ConfigJSON()
	}
	iter := jsoniter.Parse(api, logReader, bufferSize)

	return &simpleJSONParser{
		logType:  f.LogType,
		newEvent: f.NewEvent,
		iter:     iter,
		validate: validate,
		builder: ResultBuilder{
			Now:       f.Now,
			NextRowID: f.NextRowID,
		},
		logReader: logReader,
	}, nil
}

type simpleJSONParser struct {
	logType   string
	newEvent  func() interface{}
	iter      *jsoniter.Iterator
	validate  func(x interface{}) error
	builder   ResultBuilder
	logReader io.Reader
}

func (p *simpleJSONParser) ParseLog(log string) ([]*Result, error) {
	event := p.newEvent()
	p.logReader.(*strings.Reader).Reset(log)
	p.iter.Reset(p.logReader)
	p.iter.Error = nil
	p.iter.ReadVal(event)
	if err := p.iter.Error; err != nil {
		return nil, errors.Wrapf(err, "failed to read %q JSON event", p.logType)
	}
	if err := p.validate(event); err != nil {
		return nil, errors.Wrapf(err, "log event %q validation failed", p.logType)
	}
	result, err := p.builder.BuildResult(p.logType, event)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build %q log event", p.logType)
	}
	return []*Result{result}, nil
}
