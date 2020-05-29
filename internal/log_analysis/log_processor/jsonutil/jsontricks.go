package jsonutil

import (
	"bytes"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
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

func UnquoteJSON(data []byte) []byte {
	if len(data) > 1 && data[0] == '"' {
		data = data[1:]
		if n := len(data) - 1; 0 <= n && n < len(data) && data[n] == '"' {
			return data[:n]
		}
	}
	return data
}

func StripObjectDelimiters(data []byte) []byte {
	if len(data) > 0 && data[0] == '{' {
		tail := data[1:]
		if n := len(tail) - 1; 0 <= n && n < len(tail) && tail[n] == '}' {
			return tail[:n]
		}
	}
	return data
}

func JoinObjects(delimiter byte, dst, src []byte) ([]byte, error) {
	var obj []byte

	n := 0
	for len(src) > 0 {
		if pos := bytes.IndexByte(src, delimiter); 0 <= pos && pos < len(src) {
			obj, src = src[:pos], src[pos+1:]
		} else {
			obj, src = src, nil
		}
		stripped := StripObjectDelimiters(obj)
		if len(stripped) == len(obj) {
			return nil, errors.Errorf("invalid JSON object %q", obj)
		}
		if n == 0 {
			dst = append(dst, '{')
		} else {
			dst = append(dst, ',')
		}
		n++
		dst = append(dst, stripped...)
	}
	dst = append(dst, '}')
	return dst, nil
}

func ConcatObjects(api jsoniter.API, dst []byte, objects ...interface{}) ([]byte, error) {
	if len(objects) == 0 {
		return dst, nil
	}
	const delimiter = '\x00'
	offset := len(dst)

	stream := api.BorrowStream(nil)
	// Stream will be appended to dst
	stream.SetBuffer(dst)
	for _, obj := range objects {
		stream.WriteVal(obj)
		// err must be assigned before ReturnStream
		if err := stream.Error; err != nil {
			// Return the stream to the pool
			api.ReturnStream(stream)
			return dst[:offset], err
		}
		_, _ = stream.Write([]byte{delimiter})
		// _ = w.WriteByte(delimiter)
	}
	out := stream.Buffer()
	api.ReturnStream(stream)
	join, err := JoinObjects(delimiter, out[:offset], out[offset:])
	if err != nil {
		return dst, err
	}
	return out[:offset+len(join)], nil
}
