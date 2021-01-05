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

// NewJSONArrayStream creates a new JSON Array stream.
// r is the underlying io.Reader
// size is the read buffer size for the jsoniter.Iterator
// path is a path to the array value to extract elements from (empty means the input JSON is an array itself)
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

// JSONArrayStream is a log entry stream that iterates over the elements of a JSON Array.
// This can reduce memory overhead in cases log events are delivered as elements of an array instead of one per-line.
type JSONArrayStream struct {
	iter       *jsoniter.Iterator
	seek       []string
	err        error
	entry      []byte
	numEntries int64
}

// Err implements the Stream interface
func (s *JSONArrayStream) Err() error {
	if errors.Is(s.err, io.EOF) {
		return nil
	}
	return s.err
}

// Next implements the Stream interface
func (s *JSONArrayStream) Next() []byte {
	if s.err != nil {
		return nil
	}
	// On first entry we seek to the key that holds the Array (if a path is set)
	if s.numEntries == 0 && len(s.seek) > 0 {
		// Advances the iterator to the value at path
		if !seekJSONPath(s.iter, s.seek) {
			// seekJSONPath reports any seek errors without a stack on the iterator
			s.err = errors.WithStack(s.iter.Error)
			return nil
		}
	}
	// Check that the array has elements
	if !s.iter.ReadArray() {
		// If the value was not an array the iterator reports an error
		if err := s.iter.Error; err != nil {
			s.err = errors.WithStack(err)
			return nil
		}
		// The value was an empty array or null
		s.err = io.EOF
		return nil
	}

	// Initialize the entry buffer
	if s.entry == nil {
		s.entry = make([]byte, MinBufferSize)
	}

	// Read the bytes and append them to the entry buffer
	s.entry = s.iter.SkipAndAppendBytes(s.entry[:0])
	if err := s.iter.Error; err != nil {
		// Check for JSON errors
		s.err = errors.WithStack(err)
		return nil
	}
	s.numEntries++
	// Return the entry data. It is valid until the next call to Next
	return s.entry
}

// seekJSONPath advances a JSON iterator to the value at path.
// Array indexes should be passed as strings
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
		// Iterate over the object keys to find the next key
		for key := iter.ReadObject(); key != "" && iter.Error == nil; key = iter.ReadObject() {
			if key == seek {
				// The key was found, continue iteration on the value
				return seekJSONPath(iter, path)
			}
			iter.Skip()
		}
		if iter.Error == nil {
			iter.ReportError(opName, fmt.Sprintf("key %q not found", seek))
		}
		return false
	case jsoniter.ArrayValue:
		// Parse the path part as an array index
		n, err := strconv.ParseInt(seek, 10, 64)
		if err != nil || n < 0 {
			iter.ReportError(opName, fmt.Sprintf("invalid array index %q", seek))
			return false
		}

		// Seek to the nth element
		for i := int64(0); i <= n && iter.ReadArray(); i++ {
			if iter.Error != nil {
				return false
			}
			if i == n {
				return seekJSONPath(iter, path)
			}
			iter.Skip()
			if iter.Error != nil {
				return false
			}
		}
		iter.ReportError(opName, fmt.Sprintf("array index %d out of bounds", n))
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
