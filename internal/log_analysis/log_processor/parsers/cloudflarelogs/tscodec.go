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
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/tcodec"
)

var cloudflareCodec = tcodec.Join(
	&cloudflareDecoder{},
	tcodec.LayoutCodec(time.RFC3339), // encoder
)

// cloudflareDecoder decodes timestamps from cloudflare logs.
// It uses RFC3339 for string values and detects seconds/nanoseconds in number timestamps.
// To decide whether the timestamp is in seconds or nanoseconds, we check if the value is too big to be expressing seconds.
type cloudflareDecoder struct{}

func (c *cloudflareDecoder) DecodeTime(iter *jsoniter.Iterator) time.Time {
	const opName = "ParseCloudflareTimestamp"
	switch iter.WhatIsNext() {
	case jsoniter.StringValue:
		tm, err := time.Parse(time.RFC3339, iter.ReadString())
		if err != nil {
			iter.ReportError(opName, err.Error())
			return time.Time{}
		}
		return tm
	case jsoniter.NumberValue:
		n := iter.ReadInt64()
		if err := iter.Error; err != nil {
			return time.Time{}
		}
		// 1 minute nanoseconds means `3871-04-29 10:40:00 +0000 UTC`
		if n > int64(time.Minute) {
			// must be in nanos
			return time.Unix(0, n).UTC()
		}
		return time.Unix(n, 0).UTC()
	default:
		iter.ReportError(opName, "invalid JSON value")
		return time.Time{}
	}
}
