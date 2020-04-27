package numerics

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
	"strconv"

	"github.com/pkg/errors"
)

// this is an int that is read from JSON as either a string or int
type Integer int

func (i *Integer) String() string {
	if i == nil {
		return "nil"
	}
	return strconv.Itoa((int)(*i))
}

// MarshalJSON implements json.Marshaler interface
func (i *Integer) MarshalJSON() ([]byte, error) {
	if i == nil {
		return []byte(`null`), nil
	}
	return strconv.AppendInt(nil, (int64)(*i), 10), nil
}

// Overflow limits for integers regardless of platform isize
// Reference: https://stackoverflow.com/a/39571615
const (
	MinUint uint = 0 // binary: all zeroes

	// Perform a bitwise NOT to change every bit from 0 to 1
	MaxUint = ^MinUint // binary: all ones

	// Shift the binary number to the right (i.e. divide by two)
	// to change the high bit to 0
	MaxInt = int(MaxUint >> 1) // binary: all ones except high bit

	// Perform another bitwise NOT to change the high bit to 1 and
	// all other bits to 0
	MinInt = ^MaxInt // binary: all zeroes except high bit
)

// UnmarshalJSON implements json.Unmarshaler interface
func (i *Integer) UnmarshalJSON(data []byte) (err error) {
	if i == nil {
		return errors.Errorf("nil target")
	}
	data = unquoteJSON(data)
	n, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err
	}
	if n > int64(MaxInt) {
		return errors.Errorf("integer overflow")
	}
	if n < int64(MinInt) {
		return errors.Errorf("integer underflow")
	}
	*i = Integer(int(n))
	return nil
}

// Int64 decodes from both string and number json values
type Int64 int64

func (i *Int64) String() string {
	if i == nil {
		return "nil"
	}
	return strconv.FormatInt((int64)(*i), 10)
}

// MarshalJSON implements json.Marshaler interface
func (i *Int64) MarshalJSON() ([]byte, error) {
	if i == nil {
		return []byte(`null`), nil
	}
	return strconv.AppendInt(nil, (int64)(*i), 10), nil
}

func unquoteJSON(data []byte) []byte {
	if len(data) > 1 && data[0] == '"' {
		data = data[1:]
		if n := len(data) - 1; 0 <= n && n < len(data) && data[n] == '"' {
			return data[:n]
		}
	}
	return data
}

// UnmarshalJSON implements json.Unmarshaler interface
func (i *Int64) UnmarshalJSON(data []byte) error {
	if i == nil {
		return errors.Errorf("nil target")
	}
	data = unquoteJSON(data)
	n, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err
	}
	*i = Int64(n)
	return nil
}
