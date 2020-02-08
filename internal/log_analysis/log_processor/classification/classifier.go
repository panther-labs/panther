package classification

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
	"runtime/debug"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
)

// holds all parsers
var parserRegistry registry.Interface = registry.AvailableParsers()

// ClassifierAPI is the interface for a classifier
type ClassifierAPI interface {
	// Classify attempts to classify the provided log line
	Classify(log string) *ClassifierResult
	// aggregate stats
	Stats() *ClassifierStats
	// specific parser stats
	ParserStats() *ParserStats
}

// ClassifierResult is the result of the ClassifierAPI#Classify method
type ClassifierResult struct {
	// Events contains the parsed events
	// If the classification process was not successful and the log is from an
	// unsupported type, this will be nil
	Events []interface{}
	// LogType is the identified type of the log
	LogType *string
	// Line that was classified and parsed
	LogLine string
}

// NewClassifier returns a new instance of a ClassifierAPI implementation
func NewClassifier() ClassifierAPI {
	return &Classifier{}
}

// Classifier is the struct responsible for classifying data streams which are assumed to be all 1 LogType()
type Classifier struct {
	// parser selected for this data stream
	selectedParser parsers.LogParser
	// aggregate stats
	stats ClassifierStats
	// specific parser stats
	parserStats ParserStats
}

func (c *Classifier) Stats() *ClassifierStats {
	return &c.stats
}

func (c *Classifier) ParserStats() *ParserStats {
	return &c.parserStats
}

// catch panics from parsers, log and continue
func (c *Classifier) safeLogParse(log string) (parsedEvents []interface{}) {
	defer func() {
		if r := recover(); r != nil {
			var logType string
			if c.selectedParser != nil {
				logType = c.selectedParser.LogType()
			}
			zap.L().Error("parser panic",
				zap.String("parser", logType),
				zap.Error(fmt.Errorf("%v", r)),
				zap.String("stacktrace", string(debug.Stack())),
				zap.String("log", log))
			parsedEvents = nil // return indicator that parse failed
		}
	}()
	if c.selectedParser == nil { // find a parser that works
		for _, parserMetadata := range parserRegistry.Elements() {
			// must call Parser.New() because parsers can be stateful, don't share the registry parser!
			parser := parserMetadata.Parser.New()
			parsedEvents = parser.Parse(log)
			if parsedEvents != nil { // set on first SUCCESSFUL parse
				c.selectedParser = parser
				break
			}
		}
	} else {
		parsedEvents = c.selectedParser.Parse(log)
	}
	return parsedEvents
}

// Classify attempts to classify the provided log line
func (c *Classifier) Classify(log string) *ClassifierResult {
	startClassify := time.Now().UTC()
	result := &ClassifierResult{}

	if len(log) == 0 { // likely empty file, nothing to do
		return result
	}

	// update aggregate stats
	defer func() {
		result.LogLine = log // set here to get "cleaned" version
		c.stats.ClassifyTimeMicroseconds = uint64(time.Since(startClassify).Microseconds())
		c.stats.BytesProcessedCount += uint64(len(log))
		c.stats.LogLineCount++
		c.stats.EventCount += uint64(len(result.Events))
		if len(log) > 0 {
			if result.LogType == nil {
				c.stats.ClassificationFailureCount++
			} else {
				c.stats.SuccessfullyClassifiedCount++
			}
		}
	}()

	log = strings.TrimSpace(log) // often the last line has \n only, could happen mid file tho

	if len(log) == 0 { // we count above (because it is a line in the file) then skip
		return result
	}

	startParseTime := time.Now().UTC()
	result.Events = c.safeLogParse(log)
	endParseTime := time.Now().UTC()

	if c.selectedParser != nil {
		logType := c.selectedParser.LogType()

		result.LogType = &logType

		c.parserStats.LogType = logType
		c.parserStats.ParserTimeMicroseconds += uint64(endParseTime.Sub(startParseTime).Microseconds())
		c.parserStats.BytesProcessedCount += uint64(len(log))
		c.parserStats.LogLineCount++
		c.parserStats.EventCount += uint64(len(result.Events))
	}

	return result
}

// aggregate stats
type ClassifierStats struct {
	ClassifyTimeMicroseconds    uint64 // total time parsing
	BytesProcessedCount         uint64 // input bytes
	LogLineCount                uint64 // input records
	EventCount                  uint64 // output records
	SuccessfullyClassifiedCount uint64
	ClassificationFailureCount  uint64
}

// per parser stats
type ParserStats struct {
	ParserTimeMicroseconds uint64 // total time parsing
	BytesProcessedCount    uint64 // input bytes
	LogLineCount           uint64 // input records
	EventCount             uint64 // output records
	LogType                string
}
