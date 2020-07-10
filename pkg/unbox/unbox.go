// Package unbox provides unboxing helpers for scalar values
package unbox

import "time"

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

// All helpers are inlined and return the zero value if the pointer is nil

func String(s *string) string {
	if s != nil {
		return *s
	}
	return ""
}
func Int(n *int) int {
	if n != nil {
		return *n
	}
	return 0
}

func Int8(n *int8) int8 {
	if n != nil {
		return *n
	}
	return 0
}

func Int16(n *int16) int16 {
	if n != nil {
		return *n
	}
	return 0
}
func Int32(n *int32) int32 {
	if n != nil {
		return *n
	}
	return 0
}
func Int64(n *int64) int64 {
	if n != nil {
		return *n
	}
	return 0
}
func Uint(n *uint) uint {
	if n != nil {
		return *n
	}
	return 0
}
func Uint8(n *uint8) uint8 {
	if n != nil {
		return *n
	}
	return 0
}
func Uint16(n *uint16) uint16 {
	if n != nil {
		return *n
	}
	return 0
}
func Uint32(n *uint32) uint32 {
	if n != nil {
		return *n
	}
	return 0
}
func Uint64(n *uint64) uint64 {
	if n != nil {
		return *n
	}
	return 0
}

func Float32(n *float32) float32 {
	if n != nil {
		return *n
	}
	return 0
}

func Float64(n *float64) float64 {
	if n != nil {
		return *n
	}
	return 0
}

func Bool(b *bool) bool {
	if b != nil {
		return *b
	}
	return false
}

func Byte(b *byte) byte {
	if b != nil {
		return *b
	}
	return 0
}

func Time(t *time.Time) time.Time {
	if t != nil {
		return *t
	}
	var zeroTime time.Time
	return zeroTime
}
