package parsers

import (
	"errors"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/jsontricks"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/logs"
)

type Interface interface {
	Parse(log string) ([]*Result, error)
}

type Result struct {
	LogType   string
	EventTime time.Time
	JSON      []byte
}

func (r *Result) Results() []*Result {
	if r == nil {
		return nil
	}
	return []*Result{r}
}

// JSON is a configured jsoniter Pool for encoding events
var JSON = func() jsoniter.API {
	// Use same settings as jsoniter.ConfigDefault
	api := jsoniter.Config{
		EscapeHTML: true,
	}.Froze()
	return api
}()

type PantherLogEventer interface {
	PantherLogEvent() *logs.Event
}

func PackResult(logEvent PantherLogEventer) (*Result, error) {
	if logEvent == nil {
		return nil, errors.New("nil log")
	}

	event := logEvent.PantherLogEvent()
	if event == nil {
		return nil, errors.New("nil event")
	}
	meta, err := event.Meta()
	if err != nil {
		return nil, err
	}
	data, err := jsontricks.ConcatObjects(JSON, nil, logEvent, meta)
	if err != nil {
		return nil, err
	}

	return &Result{
		LogType:   event.LogType,
		EventTime: event.Timestamp,
		JSON:      data,
	}, nil
}

func QuickParseJSON(log string, logEvent PantherLogEventer) ([]*Result, error) {
	if err := jsoniter.UnmarshalFromString(log, logEvent); err != nil {
		return nil, err
	}
	if err := Validator.Struct(logEvent); err != nil {
		return nil, err
	}
	event := logEvent.PantherLogEvent()
	if event == nil {
		return nil, errors.New("nil event")
	}
	meta, err := event.Meta()
	if err != nil {
		event.Close()
		return nil, err
	}

	data, err := jsontricks.ConcatObjects(JSON, nil, logEvent, meta)
	if err != nil {
		event.Close()
		return nil, err
	}
	result := Result{
		LogType:   event.LogType,
		EventTime: event.Timestamp,
		JSON:      data,
	}
	event.Close()
	return result.Results(), nil
}
