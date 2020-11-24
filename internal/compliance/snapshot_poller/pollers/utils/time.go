package utils

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
)

var (
	// TimeNowFunc directs to the TimeNow function.
	// This is intended to be overridden for testing.
	TimeNowFunc = TimeNowRFC3339
)

// TimeNowRFC3339 returns the current time in RFC3339 format.
func TimeNowRFC3339() time.Time {
	return time.Now()
}

// ParseTimeRFC3339 parses a time string into a valid RFC3339 time.
func ParseTimeRFC3339(timeString string) time.Time {
	parsedTime, err := time.Parse(time.RFC3339, timeString)
	if err != nil {
		return time.Time{}
	}

	return parsedTime
}

// StringToDateTime parses a time string into a time.Time struct
func StringToDateTime(timeString string) *time.Time {
	result := ParseTimeRFC3339(timeString)
	return &result
}

// UnixTimeToDateTime parses an Int64 representing an epoch timestamp to a time.Time struct
func UnixTimeToDateTime(epochTimeStamp int64) *time.Time {
	result := time.Unix(epochTimeStamp, 0)
	return &result
}
