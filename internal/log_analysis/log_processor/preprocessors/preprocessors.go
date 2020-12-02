// Package preprocessors provides log pre processors
package preprocessors

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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// Interface handles processing of a log line *before* it is parsed as JSON to produce a log event.
type Interface interface {
	PreProcessLog(log string) (string, error)
}

// Pipeline applies pre-processors in order.
func Pipeline(preProcessors ...Interface) Interface {
	pipeline := make(ppPipeline, 0, len(preProcessors))
	for _, pp := range preProcessors {
		if pp == nil {
			continue
		}
		// Expand pipeline
		if expand, ok := pp.(ppPipeline); ok {
			pipeline = append(pipeline, expand...)
		} else {
			pipeline = append(pipeline, pp)
		}
	}
	if len(pipeline) == 0 {
		return nil
	}
	return pipeline
}

// Wrap wraps a parser and executes a preprocessing pipeline before the log entry is parsed.
func Wrap(parser parsers.Interface, preProcessors ...Interface) parsers.Interface {
	if parser == nil {
		return nil
	}
	pipeline := Pipeline(preProcessors...)
	if pipeline == nil {
		return parser
	}
	return &logParser{
		parser: parser,
		pre:    pipeline,
	}
}

type logParser struct {
	parser parsers.Interface
	pre    Interface
}

func (p *logParser) ParseLog(log string) ([]*pantherlog.Result, error) {
	log, err := p.pre.PreProcessLog(log)
	if err != nil {
		return nil, err
	}
	return p.parser.ParseLog(log)
}

type ppPipeline []Interface

var _ Interface = (ppPipeline)(nil)

func (chain ppPipeline) PreProcessLog(log string) (string, error) {
	for _, pp := range chain {
		next, err := pp.PreProcessLog(log)
		if err != nil {
			return "", err
		}
		log = next
	}
	return log, nil
}

// Nop is a preprocessor that doesn't modify the log entry.
func Nop() Interface {
	return &nopPreProcessor{}
}

type nopPreProcessor struct{}

func (*nopPreProcessor) PreProcessLog(log string) (string, error) {
	return log, nil
}
