package pantherlog

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

	jsoniter "github.com/json-iterator/go"
	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog/null"
)

// Re-export field types from the pantherlog package so event types only need to import a single package.
// This makes explaining the process of adding support for a new log type much easier.
// It also allows us to change implementations of a field type in the future without modifying parser code
type String = null.String
type Float64 = null.Float64
type Float32 = null.Float32
type Int64 = null.Int64
type Int32 = null.Int32
type Int16 = null.Int16
type Int8 = null.Int8
type Uint64 = null.Uint64
type Uint32 = null.Uint32
type Uint16 = null.Uint16
type Uint8 = null.Uint8
type Bool = null.Bool
type Time = time.Time
type RawMessage = jsoniter.RawMessage

func ValidateStruct(x interface{}) error {
	return validate.Struct(x)
}

var validate = func() *validator.Validate {
	v := validator.New()
	null.RegisterValidators(v)
	return v
}()
