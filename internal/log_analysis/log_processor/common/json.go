package common

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
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue/glueschema"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue/gluetimestamp"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/omitempty"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/renamefields"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

// ConfigForDataLakeWriters returns a jsoniter.API configured to be used for JSON log events written to the data-lake.
//
// WARNING: This is meant to be used for encoding ONLY FOR WRITING TO S3 Processed logs.
//          For all other uses please use pantherlog.ConfigJSON()
//          You should probably not use it.
func ConfigForDataLakeWriters() jsoniter.API {
	api := jsoniter.Config{
		EscapeHTML: true,
		// We don't need to validate JSON raw messages.
		// This option is useful for raw messages that are produced by go directly and can contain errors.
		// Our `jsoniter.RawMessage` come from decoding the input JSON so if they contained errors the parsers would
		// already have failed to read the input JSON.
		ValidateJsonRawMessage: false,
		SortMapKeys:            true,
		// Use case sensitive keys when decoding
		CaseSensitive: true,
	}.Froze()
	// Force omitempty on all struct fields
	api.RegisterExtension(omitempty.New("json"))
	// Add tcodec using the default registry
	api.RegisterExtension(&tcodec.Extension{})
	// Rename all fields according to Glue requirements
	api.RegisterExtension(renamefields.New(glueschema.ColumnName))
	// Fix all timestamps to use Glue layout and UTC
	api.RegisterExtension(tcodec.OverrideEncoders(gluetimestamp.TimeEncoder()))
	// Register pantherlog last so event_time tags work fine
	api.RegisterExtension(pantherlog.NewExtension())
	return api
}
