package logstream

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
	"fmt"
	"io"
	"strconv"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
)

func NewJSONArrayStream(r io.Reader, size int, path ...string) *JSONArrayStream {
	if size <= 0 {
		size = DefaultBufferSize
	} else if size < MinBufferSize {
		size = MinBufferSize
	}
	return &JSONArrayStream{
		iter: jsoniter.Parse(jsoniter.ConfigDefault, r, size),
		seek: path,
	}
}

type JSONArrayStream struct {
	iter       *jsoniter.Iterator
	seek       []string
	err        error
	entry      []byte
	numEntries int64
}

func (s *JSONArrayStream) Err() error {
	if errors.Is(s.err, io.EOF) {
		return nil
	}
	return s.err
}

func (s *JSONArrayStream) Next() []byte {
	if s.err != nil {
		return nil
	}
	if s.numEntries == 0 && len(s.seek) > 0 {
		if !seekJSONPath(s.iter, s.seek) {
			s.err = errors.WithStack(s.iter.Error)
			return nil
		}
	}
	if !s.iter.ReadArray() {
		if err := s.iter.Error; err != nil {
			s.err = errors.WithStack(err)
			return nil
		}
		s.err = io.EOF
		return nil
	}

	if s.entry == nil {
		s.entry = make([]byte, MinBufferSize)
	}

	s.entry = s.iter.SkipAndAppendBytes(s.entry[:0])
	if err := s.iter.Error; err != nil {
		s.err = errors.WithStack(err)
		return nil
	}
	s.numEntries++
	return s.entry
}

func seekJSONPath(iter *jsoniter.Iterator, path []string) bool {
	const opName = "seekJSONPath"
	if err := iter.Error; err != nil {
		return false
	}
	if len(path) == 0 {
		return true
	}
	seek := path[0]
	path = path[1:]
	switch t := iter.WhatIsNext(); t {
	case jsoniter.ObjectValue:
		for key := iter.ReadObject(); key != "" && iter.Error == nil; key = iter.ReadObject() {
			if key == seek {
				return seekJSONPath(iter, path)
			}
			iter.Skip()
		}
		if iter.Error == nil {
			iter.ReportError(opName, fmt.Sprintf("key %q not found", seek))
		}
		return false
	case jsoniter.ArrayValue:
		n, err := strconv.ParseInt(seek, 10, 64)
		if err != nil {
			iter.ReportError(opName, fmt.Sprintf("invalid array index %q", seek))
			return false
		}
		for i := n; i >= 0 && iter.ReadArray(); i-- {
			if i == 0 {
				return seekJSONPath(iter, path)
			}
			iter.Skip()
		}
		if iter.Error == nil {
			iter.ReportError(opName, fmt.Sprintf("array index %d out of bounds", n))
		}
		return false
	case jsoniter.StringValue:
		iter.ReportError(opName, "cannot seek into a string value")
		return false
	case jsoniter.NumberValue:
		iter.ReportError(opName, "cannot seek into a number value")
		return false
	case jsoniter.BoolValue:
		iter.ReportError(opName, "cannot seek into a bool value")
		return false
	case jsoniter.NilValue:
		iter.ReportError(opName, "cannot seek into a null value")
		return false
	default:
		if iter.Error == nil {
			iter.ReportError(opName, "invalid JSON input")
		}
		return false
	}
}
