package pantherlog

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
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/jsonutil"
)

// Result is the result of parsing a log event.
// It contains the JSON form of the pantherlog to be stored for queries.
type Result struct {
	LogType   string
	EventTime time.Time
	JSON      []byte
}

// Results wraps a single Result in a slice.
func (r *Result) Results() []*Result {
	if r == nil {
		return nil
	}
	return []*Result{r}
}

// PackResult packs an `Eventer` to a `Result`.
// It is a helper method to be used in parser implementations.
func PackResult(logEvent Eventer) (*Result, error) {
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

	// Compose the resulting JSON
	data, err := jsonutil.ConcatObjects(JSON, nil, logEvent, meta)
	if err != nil {
		return nil, err
	}

	return &Result{
		LogType:   event.LogType,
		EventTime: event.Timestamp,
		JSON:      data,
	}, nil
}

// JSON is a custom jsoniter config to properly remap field names for compatibility with Athena views
var JSON = func() jsoniter.API {
	config := jsoniter.Config{
		EscapeHTML: true,
		// Validate raw JSON messages to make sure queries work as expected
		ValidateJsonRawMessage: true,
		// We don't need sorted map keys
		SortMapKeys: false,
	}
	api := config.Froze()
	rewriteFields := jsonutil.NewEncoderNamingStrategy(RewriteFieldName)
	api.RegisterExtension(rewriteFields)
	return api
}()

// TODO: [pantherlog] Add more mappings of invalid Athena field name characters here
// NOTE: The mapping should be easy to remember (so no ASCII code etc) and complex enough
// to avoid possible conflicts with other fields.
var fieldNameReplacer = strings.NewReplacer(
	"@", "_at_sign_",
	",", "_comma_",
	"`", "_backtick_",
	"'", "_apostrophe_",
)

func RewriteFieldName(name string) string {
	result := fieldNameReplacer.Replace(name)
	if result == name {
		return name
	}
	return strings.Trim(result, "_")
}
