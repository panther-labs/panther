package parsers

import (
	"time"

	jsoniter "github.com/json-iterator/go"
)

type Result struct {
	LogType   string
	EventTime time.Time
	JSON      []byte
}

var JSON = func() jsoniter.API {
	// Use same settings as jsoniter.ConfigDefault
	api := jsoniter.Config{
		EscapeHTML: true,
	}.Froze()
	return api
}()
