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

type Demux interface {
	demux(api *jsoniter.Iterator, payload []byte) ([]byte, string)
}

func DemuxKeyValue() Demux {
	return &demuxKeyValue{}
}
func DemuxPeekKey(routeKey string) Demux {
	return &demuxPeekKey{
		routeKey: routeKey,
	}
}

func DemuxKeys(routeKey, payloadKey string) Demux {
	return &demuxKeyKey{
		routeKey:   routeKey,
		payloadKey: payloadKey,
	}
}

type demuxKeyValue struct{}

func (d *demuxKeyValue) demux(iter *jsoniter.Iterator, _ []byte) ([]byte, string) {
	name := iter.ReadObject()
	if name == "" {
		return nil, ""
	}
	return iter.SkipAndReturnBytes(), name
}

type demuxKeyKey struct {
	routeKey   string
	payloadKey string
}

func (d *demuxKeyKey) demux(iter *jsoniter.Iterator, payload []byte) (p []byte, name string) {
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

type demuxPeekKey struct {
	routeKey string
}

func (d *demuxPeekKey) demux(iter *jsoniter.Iterator, payload []byte) ([]byte, string) {
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
