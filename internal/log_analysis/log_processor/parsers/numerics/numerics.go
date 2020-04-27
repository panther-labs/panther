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
	"strings"

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

// FIXME: `nil` is not valid JSON data is this intended?
func (i *Integer) MarshalJSON() ([]byte, error) {
	return ([]byte)(i.String()), nil
}

// FIXME: unmarshalling to a nil target fails silently here, this is a weird behavior probably not intentional
func (i *Integer) UnmarshalJSON(jsonBytes []byte) (err error) {
	// FIXME: The strings.Trim call accepts invalid JSON input (ie `"42""``) as shown in the corresponding test case
	parsedInt, err := strconv.Atoi(strings.Trim((string)(jsonBytes), `"`)) // remove quotes, to int
	if err == nil && i != nil {
		*i = (Integer)(parsedInt)
	}
	return err
}

// add others below as we need them

type Int64 int64

func (i *Int64) String() string {
	if i == nil {
		return ""
	}
	return strconv.FormatInt((int64)(*i), 10)
}

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
