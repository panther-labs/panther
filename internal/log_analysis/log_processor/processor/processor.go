package processor

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
	"bufio"
	"io"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/classification"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/oplog"
)

const (
	// oplog keys
	operationName = "parse"
	statsKey      = "stats"
)

var (
	// ParsedEventBufferSize is the size of the buffer of the Go channel containing the parsed events.
	// Since there are different goroutines writing and reading from that channel each with different I/O characteristics,
	// we are specifying this buffer to avoid blocking the goroutines that write to the channel if the reader goroutine is
	// temporarily busy. The writer goroutines will block writing but only when the buffer has been full - something we need
	// to avoid using up lot of memory.
	// see also: https://golang.org/doc/effective_go.html#channels
	ParsedEventBufferSize = 1000
)

// Process orchestrates the tasks of parsing logs, classification, normalization
// and forwarding the logs to the appropriate destination. Any errors will cause Lambda invocation to fail
func Process(dataStreams chan *common.DataStream, destination destinations.Destination) error {
	factory := func(r *common.DataStream) *Processor {
		return NewProcessor(r, registry.AvailableLogTypes()...)
	}
	return process(dataStreams, destination, factory)
}

// entry point to allow customizing processor for testing
func process(dataStreams chan *common.DataStream, destination destinations.Destination,
	newProcessorFunc func(*common.DataStream) *Processor) error {

	parsedEventChannel := make(chan *pantherlog.Result, ParsedEventBufferSize)
	errorChannel := make(chan error)

	// go routine aggregates data written to s3
	var sendEventsWg sync.WaitGroup
	sendEventsWg.Add(1)
	go func() {
		destination.SendEvents(parsedEventChannel, errorChannel) // runs until parsedEventChannel is closed
		sendEventsWg.Done()
	}()

	// listen for errors, set to var below which will be returned
	var errorsWg sync.WaitGroup
	errorsWg.Add(1)
	var err error
	go func() {
		for err = range errorChannel {
		} // to ensure there are not writes to a closed channel, loop to drain
		errorsWg.Done()
	}()

	// it is important to process the streams serially to manage memory!
	for dataStream := range dataStreams {
		processor := newProcessorFunc(dataStream)
		err := processor.run(parsedEventChannel)
		if err != nil {
			errorChannel <- err
			break
		}
	}

	// Close the channel after all goroutines have finished writing to it.
	// The Destination that is reading the channel will terminate
	// after consuming all the buffered messages
	close(parsedEventChannel) // this will cause SendEvent() go routine to finish and exit
	sendEventsWg.Wait()       // wait until all files and errors are written
	close(errorChannel)       // this will allow err chan loop to finish
	errorsWg.Wait()           // wait for err chan loop to finish
	zap.L().Debug("data processing goroutines finished")

	return err
}

// processStream reads the data from an S3 the dataStream, parses it and writes events to the output channel
func (p *Processor) run(outputChan chan *pantherlog.Result) error {
	var err error
	stream := bufio.NewReader(p.input.Reader)
	for {
		var line string
		line, err = stream.ReadString(common.EventDelimiter)
		if err != nil {
			if err == io.EOF { // we are done
				err = nil // not really an error
				p.processLogLine(line, outputChan)
			}
			break
		}
		p.processLogLine(line, outputChan)
	}
	if err != nil {
		err = errors.Wrap(err, "failed to ReadString()")
	}
	p.logStats(err) // emit log line describing the processing of the file and any errors
	return err
}

func (p *Processor) processLogLine(line string, outputChan chan *pantherlog.Result) {
	classificationResult := p.classifyLogLine(line)
	if classificationResult.LogType == nil { // unable to classify, no error, keep parsing (best effort, will be logged)
		return
	}
	p.sendEvents(classificationResult, outputChan)
}

func (p *Processor) classifyLogLine(line string) *classification.ClassifierResult {
	result := p.classifier.Classify(line)
	if result.LogType == nil && len(strings.TrimSpace(line)) != 0 { // only if line is not empty do we log (often we get trailing \n's)
		if p.input.Hints.S3 != nil { // make easy to troubleshoot but do not add log line (even partial) to avoid leaking data into CW
			p.operation.LogWarn(errors.New("failed to classify log line"),
				zap.Uint64("lineNum", p.classifier.Stats().LogLineCount),
				zap.String("bucket", p.input.Hints.S3.Bucket),
				zap.String("key", p.input.Hints.S3.Key))
		}
	}
	return result
}

func (p *Processor) sendEvents(result *classification.ClassifierResult, outputChan chan *pantherlog.Result) {
	for _, event := range result.Events {
		outputChan <- event
	}
}

func (p *Processor) logStats(err error) {
	p.operation.Stop()
	p.operation.Log(err, zap.Any(statsKey, *p.classifier.Stats()))
	for _, parserStats := range p.classifier.ParserStats() {
		p.operation.Log(err, zap.Any(statsKey, *parserStats))
	}
}

type Processor struct {
	input      *common.DataStream
	classifier classification.ClassifierAPI
	operation  *oplog.Operation
}

func NewProcessor(input *common.DataStream, logTypes ...pantherlog.LogType) *Processor {
	if logTypes == nil {
		logTypes = pantherlog.AvailableLogTypes()
	}
	cls := classification.NewClassifier(logTypes...).(*classification.Classifier)
	return &Processor{
		input:      input,
		classifier: cls,
		operation:  common.OpLogManager.Start(operationName),
	}
}
