package numerics

/**
 * A Cloud-Native SIEM for the Modern Security Team
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
)

// this is an int that is read from JSON as either a string or int
type Integer int

func (i *Integer) String() string {
	if i == nil {
		return "nil"
	}
	return strconv.Itoa((int)(*i))
}

func (i *Integer) MarshalJSON() ([]byte, error) {
	return ([]byte)(i.String()), nil
}

func (i *Integer) UnmarshalJSON(jsonBytes []byte) (err error) {
	parsedInt, err := strconv.Atoi(strings.Trim((string)(jsonBytes), `"`)) // remove quotes, to int
	if err == nil && i != nil {
		*i = (Integer)(parsedInt)
	}
	return err
}

// add others below as we need them
