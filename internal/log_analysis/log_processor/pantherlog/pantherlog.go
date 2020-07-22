// Package pantherlog defines types and functions to parse logs for Panther
package pantherlog

import (
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/jsonutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

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

// EventStruct composes a struct that extends `event` with panther fields
func EventStruct(event interface{}) interface{} {
	return defaultMetaFields.EventStruct(event)
}

// BuildResult builds a result using the default meta fields
func BuildResult(logType string, event interface{}) (*Result, error) {
	builder := ResultBuilder{
		LogType: logType,
	}
	return builder.BuildResult(event)
}

// JSON returns a customized jsoniter.API to be used for serializing panthe log events.
func JSON() jsoniter.API {
	return jsonAPI
}

var jsonAPI = RegisterExtensions(jsoniter.Config{
	EscapeHTML: true,
	// Validate raw JSON messages to make sure queries work as expected
	ValidateJsonRawMessage: true,
	SortMapKeys:            true,
}.Froze())

// RegisterExtensions registers all pantherlog required extensions on an API
func RegisterExtensions(api jsoniter.API) jsoniter.API {
	api.RegisterExtension(jsonutil.NewEncoderNamingStrategy(awsglue.RewriteFieldName))
	tcodec.RegisterJSONEncoder(api, awsglue.TimestampLayout, time.UTC)
	api.RegisterExtension(tcodec.NewDecoderExtension())
	api.RegisterExtension(jsonutil.NewOmitempty("json"))
	api.RegisterExtension(&scanValueEncodersExt{})
	api.RegisterExtension(&customEncodersExt{})
	api.RegisterExtension(&eventTimeExt{})
	return api
}
