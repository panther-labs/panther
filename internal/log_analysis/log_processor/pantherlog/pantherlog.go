// Package pantherlog defines types and functions to parse logs for Panther
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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"reflect"
	"time"

	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common/null"
)

type Event interface {
	PantherLogEvent() (string, *time.Time)
}

func EventStruct(event Event) interface{} {
	return defaultMetaFields.EventStruct(event)
}
func RegisterValidators(v *validator.Validate) {
	// Register null values
	null.RegisterValidators(v)

	// Register scanners
	for typ := range scannerMappings {
		v.RegisterCustomTypeFunc(func(v reflect.Value) interface{} {
			return v.Field(0).String()
		}, reflect.New(typ).Elem().Interface())
	}

	// Register enums
	for typ := range registeredEnums {
		v.RegisterCustomTypeFunc(func(v reflect.Value) interface{} {
			return v.Field(0).String()
		}, reflect.New(typ).Elem().Interface())
	}
}
