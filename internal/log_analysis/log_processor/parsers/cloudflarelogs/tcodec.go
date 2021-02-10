package cloudflarelogs

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
	"io"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

// Handle the decoding for RFC3339 using the LayoutCodec method
var decodeRFC3339 = tcodec.LayoutCodec(time.RFC3339).DecodeTime

type timeDecoder struct{}

// DecodeTime implements tcodec.TimeDecoder for timestamps in cloudflare logs.
// It uses RFC3339 for string values and detects seconds/nanoseconds in number timestamps.
// To decide whether the timestamp is in seconds or nanoseconds, we check if the value is too big to be expressing seconds.
func (c *timeDecoder) DecodeTime(iter *jsoniter.Iterator) time.Time {
	const opName = "ParseCloudflareTimestamp"
	switch iter.WhatIsNext() {
	case jsoniter.StringValue:
		// If the value is a string we use the RFC3339 layout.
		return decodeRFC3339(iter)
	case jsoniter.NumberValue:
		// Cloudflare unix timestamps are integers of either seconds or nanoseconds
		n := iter.ReadInt64()
		if err := iter.Error; err != nil {
			// This is a weird behavior of jsoniter only trigered when the parsed JSON is just a number
			if err != io.EOF {
				return time.Time{}
			}
			iter.Error = nil
		}
		// Detect if it's nanoseconds or seconds
		// 60000000000 seconds since UNIX epoch is `3871-04-29 10:40:00 +0000 UTC`
		const maxSeconds = int64(time.Minute)
		if n < maxSeconds {
			// timestamp is expressed in seconds
			return time.Unix(n, 0).UTC()
		}
		// timestamp is expressed in nanoseconds
		return time.Unix(0, n).UTC()
	default:
		iter.Skip()
		iter.ReportError(opName, "invalid JSON value")
		return time.Time{}
	}
}
