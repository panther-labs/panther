// Package gluetimestamp handles encoding/decoding of timestamp values for AWS glue.
package gluetimestamp

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

const (
	// We want our output JSON timestamps to be: YYYY-MM-DD HH:MM:SS.fffffffff
	// https://aws.amazon.com/premiumsupport/knowledge-center/query-table-athena-timestamp-empty/
	Layout     = `2006-01-02 15:04:05.000000000`
	LayoutJSON = `"` + Layout + `"`
)

// TimeEncoder returns a time encoder all timestamps to be Glue format and UTC.
func TimeEncoder() tcodec.TimeEncoder {
	return &timeEncoder{}
}

type timeEncoder struct{}

func (*timeEncoder) EncodeTime(tm time.Time, stream *jsoniter.Stream) {
	if tm.IsZero() {
		stream.WriteNil()
		return
	}
	// Avoid allocations by using AppendFormat directly on the buffer
	buf := stream.Buffer()
	buf = tm.UTC().AppendFormat(buf, LayoutJSON)
	stream.SetBuffer(buf)
}
