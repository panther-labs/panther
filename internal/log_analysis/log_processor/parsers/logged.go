package parsers

import (
	"fmt"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"go.uber.org/zap"
	"reflect"
)

// WithLogger logs errors and results of a log parser.
// Parser errors are logged at ERROR level.
// Parser results are logged at DEBUG level.
// Swaps loggers if `parser` argument already has logger.
// Removes logging if `parser` argument already has logger and `logger` is `nil`.
// Returns `parser` argument untouched if `logger` is `nil`.
func WithLogger(parser Interface, logger *zap.Logger) Interface {
	// Switch logger
	if logged, ok := parser.(*loggedParser); ok {
		if logger == nil {
			return logged.LogParser
		}
		return logged
	}

	// Return parser untouched if no logger is provided
	if logger == nil {
		return parser
	}

	// Use the inner parser for the error message
	inner := parser
	if m, ok := parser.(*Metered); ok {
		inner = m.Parser()
	}
	typeName := reflect.Indirect(reflect.ValueOf(inner)).Type().String()
	return &loggedParser{
		LogParser:    parser,
		failMessage:  fmt.Sprintf(`%s.ParseLog() failed`, typeName),
		debugMessage: fmt.Sprintf(`%s.ParseLog() results`, typeName),
		logger:       logger,
	}
}

type loggedParser struct {
	pantherlog.LogParser
	logger       *zap.Logger
	failMessage  string
	debugMessage string
}

func (p *loggedParser) ParseLog(log string) ([]*pantherlog.Result, error) {
	results, err := p.LogParser.ParseLog(log)
	if err != nil {
		p.logger.Error(p.failMessage, zap.Error(err))
	} else {
		p.logger.Debug(p.debugMessage, zap.Any(`results`, results))
	}
	return results, err
}
