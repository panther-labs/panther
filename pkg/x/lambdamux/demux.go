package lambdamux

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
)

// Demuxer sets the routing strategy for a payload.
//
// It accepts the current JSON iterator and the original payload and returns the route payload and name.
type Demuxer interface {
	Demux(iter *jsoniter.Iterator, payload []byte) ([]byte, string)
}

// DemuxKeyValue uses the first key in a JSON object as route name and it's value as payload.
//
// For example a `DemuxKeyValue()` will route a payload `{"foo":{"bar":"baz"}}`
// to route `foo` with payload `{"bar":"baz"}`.
func DemuxKeyValue() Demuxer {
	return &demuxKeyValue{}
}

type demuxKeyValue struct{}

func (d *demuxKeyValue) Demux(iter *jsoniter.Iterator, _ []byte) ([]byte, string) {
	name := iter.ReadObject()
	if name == "" {
		return nil, ""
	}
	return iter.SkipAndReturnBytes(), name
}

// DemuxPeekKey peeks into the value of a JSON object field to find the route name.
//
// For example a `DemuxPeekKey("method")` will route a payload `{"method":"foo", "bar":"baz"}}`
// to route `foo` with payload `{"method":"foo", "bar":"baz"}`.
func DemuxPeekKey(routeKey string) Demuxer {
	return &demuxPeekKey{
		routeKey: routeKey,
	}
}

type demuxPeekKey struct {
	routeKey string
}

func (d *demuxPeekKey) Demux(iter *jsoniter.Iterator, payload []byte) ([]byte, string) {
	for key := iter.ReadObject(); key != ""; key = iter.ReadObject() {
		if key != d.routeKey {
			iter.Skip()
			continue
		}
		name := iter.ReadString()
		if name == "" {
			return nil, ""
		}
		return payload, name
	}
	return nil, ""
}

// DemuxKeys uses the value of two separate keys of a JSON object as route name and payload.
//
// For example a `DemuxKeys("method","params")` will route a payload `{"method": "foo", "params":{"bar":"baz"}}`
// to route `foo` with payload `{"bar":"baz"}`.
//
func DemuxKeys(routeKey, payloadKey string) Demuxer {
	return &demuxKeys{
		routeKey:   routeKey,
		payloadKey: payloadKey,
	}
}

type demuxKeys struct {
	routeKey   string
	payloadKey string
}

func (d *demuxKeys) Demux(iter *jsoniter.Iterator, payload []byte) (p []byte, name string) {
	for key := iter.ReadObject(); key != ""; key = iter.ReadObject() {
		switch key {
		case d.routeKey:
			name = iter.ReadString()
			if p != nil {
				return p, name
			}
		case d.payloadKey:
			if name != "" {
				return iter.SkipAndReturnBytes(), name
			}
			p = iter.SkipAndAppendBytes(make([]byte, 0, len(payload)))
		default:
			iter.Skip()
		}
	}
	return nil, ""
}
