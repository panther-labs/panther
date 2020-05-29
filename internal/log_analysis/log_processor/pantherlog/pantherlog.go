// Package pantherlog defines types and functions to parse logs for Panther
package pantherlog

import (
	"bufio"
	"context"
	jsoniter "github.com/json-iterator/go"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/pkg/errors"
	"io"
	"strings"
)

// LogType describes a log type.
// It provides a method to create a new parser and a schema struct to derive
// tables from. LogTypes can be grouped in a `Registry` to have an index of available
// log types.
type LogType struct {
	Name        string
	Description string
	Schema      interface{}
	NewParser   func() LogParser
	NewScanner  func(r io.Reader) LogScanner
}

type LogParser interface {
	ParseLog(log string) ([]*Result, error)
}

func (t *LogType) Parser() LogParser {
	return t.NewParser()
}

func (t *LogType) Scanner(r io.Reader) LogScanner {
	if t.NewScanner != nil {
		return t.NewScanner(r)
	}
	return ScanLogLines(r)
}

// GlueTableMetadata returns metadata about the glue table based on LogType.Schema
func (t *LogType) GlueTableMetadata() *awsglue.GlueTableMetadata {
	return awsglue.NewLogTableMetadata(t.Name, t.Description, t.Schema)
}

func (t *LogType) Check() error {
	if t == nil {
		return errors.Errorf("nil log type entry")
	}
	if t.Name == "" {
		return errors.Errorf("missing entry log type")
	}
	if t.Description == "" {
		return errors.Errorf("missing description for log type %q", t.Name)
	}
	// describes Glue table over processed data in S3
	// assert it does not panic here until some validation method is provided
	// TODO: [awsglue] Add some validation for the metadata in `awsglue` package
	_ = awsglue.NewLogTableMetadata(t.Name, t.Description, t.Schema)

	return checkLogEntrySchema(t.Name, t.Schema)
}

// ParserFactory creates a new parser instance.
type ParserFactory func() LogParser

type LogScanner interface {
	ScanLog() (string, error)
}

func ScanLogLines(r io.Reader) LogScanner {
	if r, ok := r.(*bufio.Reader); ok {
		return &logScannerLines{
			r: r,
		}
	}
	return &logScannerLines{
		r: bufio.NewReader(r),
	}
}

type logScannerLines struct {
	r         *bufio.Reader
	numLines  int64
	totalSize int64
}

func (s *logScannerLines) ScanLog() (string, error) {
	b := strings.Builder{}
	if s.numLines != 0 {
		// Pre-allocate to average line size
		size := s.totalSize / s.numLines
		b.Grow(int(size))
	}
	for {
		line, isPrefix, err := s.r.ReadLine()
		s.totalSize += int64(len(line))
		b.Write(line)
		if err != nil {
			return b.String(), err
		}
		if isPrefix {
			continue
		}
		s.numLines++
		return b.String(), nil
	}
}

func ScanLogJSON(r io.Reader) LogScanner {
	iter := jsoniter.ConfigFastest.BorrowIterator(nil)
	iter.Reset(r)
	return &logScannerJSON{
		iter: iter,
	}
}

type logScannerJSON struct {
	iter *jsoniter.Iterator
	msg  jsoniter.RawMessage
}

func (s *logScannerJSON) ScanLog() (string, error) {
	if err := s.iter.Error; err != nil {
		return "", err
	}
	s.iter.ReadVal(&s.msg)
	if err := s.iter.Error; err != nil {
		return "", err
	}
	return string(s.msg), nil
}

func checkLogEntrySchema(logType string, schema interface{}) error {
	if schema == nil {
		return errors.Errorf("nil schema for log type %q", logType)
	}
	data, err := jsoniter.Marshal(schema)
	if err != nil {
		return errors.Errorf("invalid schema struct for log type %q: %s", logType, err)
	}
	var fields map[string]interface{}
	if err := jsoniter.Unmarshal(data, &fields); err != nil {
		return errors.Errorf("invalid schema struct for log type %q: %s", logType, err)
	}
	// TODO: [parsers] Use reflect to check provided schema struct for required panther fields
	return nil
}

type LogHandler interface {
	Results() <-chan *Result
	Run(ctx context.Context) error
}

type logHandler struct {
	results chan *Result
	parser  LogParser
	scanner LogScanner
	ctx     context.Context
}

func (h *logHandler) Run(ctx context.Context) error {
	if h.ctx != nil {
		return errors.New("already running")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	done := ctx.Done()
	for {
		log, err := h.scanner.ScanLog()
		if err != nil {
			return err
		}
		results, err := h.parser.ParseLog(log)
		if err != nil {
			return err
		}
		for _, result := range results {
			select {
			case <-done:
				return ctx.Err()
			case h.results <- result:
			}
		}
	}
}

func (h *logHandler) Results() <-chan *Result {
	return h.results
}

func (t *LogType) Handler(r io.Reader) LogHandler {
	return &logHandler{
		results: make(chan *Result, 0),
		parser:  t.Parser(),
		scanner: t.Scanner(r),
	}
}
