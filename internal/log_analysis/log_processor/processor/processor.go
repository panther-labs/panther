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
	"context"
	"sync"

	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/classification"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	logmetrics "github.com/panther-labs/panther/internal/log_analysis/log_processor/metrics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
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

type ProcessFunc func(streamCh <-chan *common.DataStream, dest destinations.Destination) error

// Process orchestrates the tasks of parsing logs, classification, normalization
// and forwarding the logs to the appropriate destination. Any errors will cause Lambda invocation to fail
func Process(
	ctx context.Context,
	dataStreams <-chan *common.DataStream,
	destination destinations.Destination,
	newProcessor func(stream *common.DataStream) (*Processor, error),
) error {

	var (
		wg             sync.WaitGroup
		err            error
		resultsChannel = make(chan *parsers.Result, ParsedEventBufferSize)
		errorChannel   = make(chan error)
		// Process streams serially to keep memory requirements low
		processStreams = func() error {
			defer close(resultsChannel)
			// it is important to process the streams serially to manage memory!
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case stream, ok := <-dataStreams:
					if !ok {
						return nil
					}
					if err := processDataStream(ctx, stream, resultsChannel, newProcessor); err != nil {
						return err
					}
				}
			}
		}
	)

	wg.Add(1)
	// Write results and return error(s) via the channel
	go func() {
		defer wg.Done()
		destination.SendEvents(resultsChannel, errorChannel) // runs until results channel is closed
	}()

	wg.Add(1)
	// Process all streams and return error via the channel
	go func() {
		defer wg.Done()
		if err := processStreams(); err != nil {
			errorChannel <- err
		}
	}()
	go func() {
		// Close the errorChannel to broadcast end of task
		defer close(errorChannel)
		// Wait until both processor loop and destination have finished
		wg.Wait()
	}()
	// collect errors
	for e := range errorChannel {
		err = multierr.Append(err, e)
	}
	zap.L().Debug("data processing goroutines finished")
	return err
}

func processDataStream(
	ctx context.Context,
	dataStream *common.DataStream,
	resultsChannel chan *parsers.Result,
	newProcessor func(stream *common.DataStream) (*Processor, error)) error {

	// ensure resources are freed
	if c := dataStream.Closer; c != nil {
		defer func() {
			if err := c.Close(); err != nil {
				zap.L().Warn("failed to close data stream",
					zap.String("sourceId", dataStream.Source.IntegrationID),
					zap.String("sourceLabel", dataStream.Source.IntegrationLabel),
					zap.Error(err))
			}
		}()
	}

	processor, err := newProcessor(dataStream)
	if err != nil {
		zap.L().Error("failed to build log processor for source",
			zap.String("sourceId", dataStream.Source.IntegrationID),
			zap.String("sourceLabel", dataStream.Source.IntegrationLabel),
			zap.Error(err))
		return err
	}
	return processor.run(ctx, resultsChannel)
}

type Processor struct {
	input      *common.DataStream
	classifier classification.ClassifierAPI
	operation  *oplog.Operation
}

type Factory func(r *common.DataStream) (*Processor, error)

func NewFactory(resolver pantherlog.ParserResolver) Factory {
	return func(input *common.DataStream) (*Processor, error) {
		switch src := input.Source; src.IntegrationType {
		case models.IntegrationTypeSqs:
			return &Processor{
				operation: common.OpLogManager.Start(operationName),
				input:     input,
				classifier: &sources.SQSClassifier{
					Resolver:   resolver,
					LoadSource: sources.LoadSource,
				},
			}, nil
		case models.IntegrationTypeAWS3:
			var availableLogTypes []string
			// S3 sources has multiple prefix<>logtypes mappings specified.
			if m, matched := src.S3PrefixLogTypes.LongestPrefixMatch(input.S3ObjectKey); matched {
				availableLogTypes = m.LogTypes
			}
			c, err := sources.BuildClassifier(availableLogTypes, src, resolver)
			if err != nil {
				return nil, err
			}
			return &Processor{
				operation:  common.OpLogManager.Start(operationName),
				input:      input,
				classifier: c,
			}, nil
		case models.IntegrationTypeAWSScan:
			c, err := sources.BuildClassifier(src.RequiredLogTypes(), src, resolver)
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
}

// processStream reads the data from an S3 the dataStream, parses it and writes events to the output channel
func (p *Processor) run(ctx context.Context, outputChan chan<- *parsers.Result) (err error) {
	// Instrument downloads. The time will include time to parse the file.
	// NOTE: dashboards depend on the operation name below! Do not change w/out updating dashboard
	operation := common.OpLogManager.Start("readS3Object", common.OpLogS3ServiceDim)
	defer func() {
		p.logStats(err) // emit log line describing the processing of the file and any errors
		operation.Stop()
		operation.Log(err,
			// s3 dim info
			zap.String("bucket", p.input.S3Bucket),
			zap.String("key", p.input.S3ObjectKey),
			zap.String("sourceID", p.input.Source.IntegrationID),
		)
	}()
	stream := p.input.Stream
	for {
		line := stream.Next()
		if line == nil {
			break
		}
		p.processLogLine(ctx, string(line), outputChan)
	}
	if err = stream.Err(); err != nil {
		err = errors.Wrap(err, "failed to read log line")
	}
	return
}

func (p *Processor) processLogLine(ctx context.Context, line string, outputChan chan<- *parsers.Result) {
	result, err := p.classifier.Classify(line)
	// A classifier returns an error when it cannot classify a non-empty log line
	if err != nil {
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
		select {
		case outputChan <- event:
		case <-ctx.Done():
			return
		}
	}
}

func (p *Processor) logStats(err error) {
	p.operation.Stop()
	p.operation.Log(err, zap.Any(statsKey, *p.classifier.Stats()))
	for _, stats := range p.classifier.ParserStats() {
		logmetrics.BytesProcessed.With(metrics.LogTypeDimension, stats.LogType).Add(float64(stats.BytesProcessedCount))
		logmetrics.EventsProcessed.With(metrics.LogTypeDimension, stats.LogType).Add(float64(stats.EventCount))
	}
}
