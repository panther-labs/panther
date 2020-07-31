// Package pantherlog defines types and functions to parse logs for Panther
package pantherlog

import (
	jsoniter "github.com/json-iterator/go"
	"github.com/modern-go/reflect2"
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

// RegisterExtensions registers all jsoniter.Extensions required to process pantherlog events.
func RegisterExtensions(api jsoniter.API) jsoniter.API {
	// Encode all Result instances using our custom encoder
	api.RegisterExtension(jsoniter.EncoderExtension{
		reflect2.TypeOf(Result{}): &resultEncoder{},
	})
	// Scan values based on `panther` tag
	api.RegisterExtension(&scanValueEncodersExt{})
	// Scan values from ValueWriterTo types
	api.RegisterExtension(&customEncodersExt{})
	// Set result event time with `panther:"event_time"`
	api.RegisterExtension(&eventTimeExt{})
	return api
}
