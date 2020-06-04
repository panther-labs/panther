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
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
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
	rewriteFields := jsonutil.NewEncoderNamingStrategy(awsglue.RewriteFieldName)
	api.RegisterExtension(rewriteFields)
	return api
}()
