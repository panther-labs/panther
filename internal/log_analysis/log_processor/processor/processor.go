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

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/classification"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
	"github.com/panther-labs/panther/internal/log_analysis/message_forwarder/forwarder"
	"github.com/panther-labs/panther/pkg/metrics"
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
		return MustBuildProcessor(r, registry.Default())
	}
	return process(dataStreams, destination, factory)
}

// entry point to allow customizing processor for testing
func process(dataStreams chan *common.DataStream, destination destinations.Destination,
	newProcessorFunc func(*common.DataStream) *Processor) error {

	parsedEventChannel := make(chan *parsers.Result, ParsedEventBufferSize)
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
func (p *Processor) run(outputChan chan *parsers.Result) error {
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

func (p *Processor) processLogLine(line string, outputChan chan *parsers.Result) {
	result, err := p.classifier.Classify(line)
	if err != nil {
		if line == "" {
			return
		}
		//FIXME: remove this after debug
		zap.L().Debug("classification failed",
			zap.String("line", line),
			zap.Error(err),
			zap.Uint64("lineNum", p.classifier.Stats().LogLineCount),
			zap.String("sourceId", p.input.Source.IntegrationID),
			zap.String("sourceLabel", p.input.Source.IntegrationLabel),
			zap.String("s3Bucket", p.input.S3Bucket),
			zap.String("s3ObjectKey", p.input.S3ObjectKey),
		)
		// make easy to troubleshoot but do not add log line (even partial) to avoid leaking data into CW
		p.operation.LogWarn(errors.New("failed to classify log line"),
			zap.Uint64("lineNum", p.classifier.Stats().LogLineCount),
			zap.String("sourceId", p.input.Source.IntegrationID),
			zap.String("sourceLabel", p.input.Source.IntegrationLabel),
			zap.String("s3Bucket", p.input.S3Bucket),
			zap.String("s3ObjectKey", p.input.S3ObjectKey),
		)
		return
	}
	if result == nil {
		return
	}
	for _, event := range result.Events {
		outputChan <- event
	}
}

func (p *Processor) logStats(err error) {
	p.operation.Stop()
	p.operation.Log(err, zap.Any(statsKey, *p.classifier.Stats()))
	logType := metrics.Dimension{Name: "LogType"}
	pMetrics := []metrics.Metric{
		{Name: "BytesProcessed"},
		{Name: "EventsProcessed"},
		{Name: "CombinedLatency"},
	}
	for _, parserStats := range p.classifier.ParserStats() {
		p.operation.Log(err, zap.Any(statsKey, *parserStats))
		logType.Value = parserStats.LogType
		pMetrics[0].Value, pMetrics[1].Value, pMetrics[2].Value =
			parserStats.BytesProcessedCount, parserStats.EventCount, parserStats.CombinedLatency
		common.BytesProcessedLogger.Log(pMetrics, logType)
	}
}

type Processor struct {
	input      *common.DataStream
	classifier classification.ClassifierAPI
	operation  *oplog.Operation
}

func MustBuildProcessor(input *common.DataStream, registry *logtypes.Registry) *Processor {
	proc, err := BuildProcessor(input, registry)
	if err != nil {
		zap.L().Error("invalid build log processor for source",
			zap.String(`source_id`, input.Source.IntegrationID),
			zap.String(`source_label`, input.Source.IntegrationLabel),
			zap.Error(err))
		panic(err)
	}
	return proc
}

func BuildProcessor(input *common.DataStream, registry *logtypes.Registry) (*Processor, error) {
	switch src := input.Source; src.IntegrationType {
	case models.IntegrationTypeSqs:
		return &Processor{
			operation: common.OpLogManager.Start(operationName),
			input:     input,
			classifier: &sqsClassifier{
				registry:    registry,
				classifiers: make(map[string]classification.ClassifierAPI),
			},
		}, nil
	case models.IntegrationTypeAWS3:
		c, err := sources.BuildClassifier(src, registry)
		if err != nil {
			return nil, err
		}
		return &Processor{
			operation:  common.OpLogManager.Start(operationName),
			input:      input,
			classifier: c,
		}, nil
	default:
		return nil, errors.Errorf("invalid source type %s", src.IntegrationType)
	}
}

type sqsClassifier struct {
	registry    *logtypes.Registry
	classifiers map[string]classification.ClassifierAPI
}

var _ classification.ClassifierAPI = (*sqsClassifier)(nil)

var jsonAPI = common.BuildJSON()

func (c *sqsClassifier) Stats() *classification.ClassifierStats {
	stats := &classification.ClassifierStats{}
	for _, child := range c.classifiers {
		stats.Add(child.Stats())
	}
	return stats
}

func (c *sqsClassifier) ParserStats() map[string]*classification.ParserStats {
	stats := map[string]*classification.ParserStats{}
	for _, child := range c.classifiers {
		childStats := child.ParserStats()
		if childStats == nil {
			continue
		}
		classification.MergeParserStats(stats, childStats)
	}
	return stats
}

func (c *sqsClassifier) Classify(log string) (*classification.ClassifierResult, error) {
	msg := forwarder.Message{}
	err := jsonAPI.UnmarshalFromString(log, &msg)
	if err != nil {
		// This is a nasty workaround because we don't handle JSONL properly and we rely on line splitting
		if len(strings.TrimSpace(log)) == 0 {
			return &classification.ClassifierResult{}, nil
		}
		return nil, err
	}
	cls, ok := c.classifiers[msg.SourceIntegrationID]
	if !ok {
		cls, err = c.buildClassifier(msg.SourceIntegrationID)

		if err != nil {
			// Just update the stats
			return nil, err
		}
		c.classifiers[msg.SourceIntegrationID] = cls
	}
	return cls.Classify(log)
}

func (c *sqsClassifier) buildClassifier(id string) (classification.ClassifierAPI, error) {
	src := sources.Lookup(id)
	if src == nil {
		return nil, errors.Errorf("unknown source id %q", id)
	}
	return sources.BuildClassifier(src, c.registry)
}
