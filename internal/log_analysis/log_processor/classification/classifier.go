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
	"container/heap"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

// ClassifierAPI is the interface for a classifier
type ClassifierAPI interface {
	// Classify attempts to classify the provided log line
	Classify(log string) *ClassifierResult
	// aggregate stats
	Stats() *ClassifierStats
	// per-parser stats, map of LogType -> stats
	ParserStats() map[string]*ParserStats
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
	parserQueue := &ParserPriorityQueue{}
	parserQueue.initialize()
	return &Classifier{
		parsers:     parserQueue,
		parserStats: make(map[string]*ParserStats),
	}
}

// Classifier is the struct responsible for classifying logs
type Classifier struct {
	parsers *ParserPriorityQueue
	// aggregate stats
	stats ClassifierStats
	// per-parser stats, map of LogType -> stats
	parserStats map[string]*ParserStats
}

func (c *Classifier) Stats() *ClassifierStats {
	return &c.stats
}

func (c *Classifier) ParserStats() map[string]*ParserStats {
	return c.parserStats
}

// catch panics from parsers, log and continue
func safeLogParse(parser parsers.LogParser, log string) (parsedEvents []interface{}) {
	defer func() {
		if r := recover(); r != nil {
			zap.L().Error("parser panic",
				zap.String("parser", parser.LogType()),
				zap.Error(fmt.Errorf("%v", r)),
				zap.String("stacktrace", string(debug.Stack())),
				zap.String("log", log))
			parsedEvents = nil // return indicator that parse failed
		}
	}()
	parsedEvents = parser.Parse(log)
	return parsedEvents
}

// Classify attempts to classify the provided log line
func (c *Classifier) Classify(log string) *ClassifierResult {
	startClassify := time.Now().UTC()
	// Slice containing the popped queue items
	var popped []interface{}
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

	for c.parsers.Len() > 0 {
		currentItem := c.parsers.Peek()

		startParseTime := time.Now().UTC()
		parsedEvents := safeLogParse(currentItem.parser, log)
		endParseTime := time.Now().UTC()

		logType := currentItem.parser.LogType()

		// Parser failed to parse event
		if parsedEvents == nil {
			zap.L().Debug("failed to parse event", zap.String("expectedLogType", currentItem.parser.LogType()))
			// Removing parser from queue
			popped = append(popped, heap.Pop(c.parsers))
			// Increasing penalty of the parser
			// Due to increased penalty the parser will be lower priority in the queue
			currentItem.penalty++
			// record failure
			continue
		}

		// Since the parsing was successful, remove all penalty from the parser
		// The parser will be higher priority in the queue
		currentItem.penalty = 0
		result.LogType = aws.String(logType)
		result.Events = parsedEvents

		// update per-parser stats
		var parserStat *ParserStats
		var parserStatExists bool
		// lazy create
		if parserStat, parserStatExists = c.parserStats[logType]; !parserStatExists {
			parserStat = &ParserStats{
				LogType: logType,
			}
			c.parserStats[logType] = parserStat
		}
		parserStat.ParserTimeMicroseconds += uint64(endParseTime.Sub(startParseTime).Microseconds())
		parserStat.BytesProcessedCount += uint64(len(log))
		parserStat.LogLineCount++
		parserStat.EventCount += uint64(len(result.Events))

		break
	}

	// Put back the popped items to the ParserPriorityQueue.
	for _, item := range popped {
		heap.Push(c.parsers, item)
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
