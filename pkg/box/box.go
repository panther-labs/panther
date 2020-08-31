// Package box provides boxing helpers for scalar values.
// This package exists to help the transition form pointer based fields to `null` fields
package box

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

// All helpers are inlined by the compiler

func String(s string) *string {
	return &s
}

func NonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func Int(n int) *int {
	return &n
}

func Int8(n int8) *int8 {
	return &n
}

func Int16(n int16) *int16 {
	return &n
}

func Int32(n int32) *int32 {
	return &n
}

func Int64(n int64) *int64 {
	return &n
}

func Uint(n uint) *uint {
	return &n
}

func Uint8(n uint8) *uint8 {
	return &n
}

func Uint16(n uint16) *uint16 {
	return &n
}

func Uint32(n uint32) *uint32 {
	return &n
}

func Uint64(n uint64) *uint64 {
	return &n
}

func Float32(n float32) *float32 {
	return &n
}

func Float64(n float64) *float64 {
	return &n
}

func Bool(b bool) *bool {
	return &b
}
func Byte(b byte) *byte {
	return &b
}

func Time(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
