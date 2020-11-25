package glueschema

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
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"time"

	jsoniter "github.com/json-iterator/go"
)

var defaultMappings = map[reflect.Type]Type{
	reflect.TypeOf(time.Time{}):           TypeTimestamp,
	reflect.TypeOf(big.Int{}):             TypeBigInt,
	reflect.TypeOf(json.RawMessage{}):     TypeString,
	reflect.TypeOf(jsoniter.RawMessage{}): TypeString,
}

func MustRegisterMapping(from reflect.Type, to Type) {
	if err := RegisterMapping(from, to); err != nil {
		panic(err)
	}
}

func RegisterMapping(from reflect.Type, to Type) error {
	if typ, duplicate := defaultMappings[from]; duplicate {
		// This is an original error, stack should be added at the caller
		return fmt.Errorf("duplicate mapping %q", typ)
	}
	defaultMappings[from] = to
	return nil
}
