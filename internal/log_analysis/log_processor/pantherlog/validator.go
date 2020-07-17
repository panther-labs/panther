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
	"reflect"

	"gopkg.in/go-playground/validator.v9"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common/null"
)

var (
	validate = validator.New()
)

func ValidateStruct(s interface{}) error {
	return validate.Struct(s)
}

func RegisterCustomTypeFunc(fn validator.CustomTypeFunc, types ...interface{}) {
	validate.RegisterCustomTypeFunc(fn, types...)
}

func init() {
	validateEmbedded := func(val reflect.Value) interface{} {
		return val.Field(0).Field(0).String()
	}
	null.RegisterValidators(validate)
	validate.RegisterCustomTypeFunc(validateEmbedded,
		IPAddress{},
		Domain{},
		Hostname{},
		TraceID{},
		SHA256{},
		SHA1{},
		MD5{},
		URL{},
	)
}
