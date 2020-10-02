package resources

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
	"fmt"

	jsoniter "github.com/json-iterator/go"
	"gopkg.in/go-playground/validator.v9"
)

var validate = validator.New()

// Parse and validate custom resource properties, storing them in "out"
//
// Out must be a pointer to a struct with appropriate `validate` tags
func parseProperties(params map[string]interface{}, out interface{}) error {
	if params == nil {
		params = make(map[string]interface{})
	}

	// We could manually use reflection on the output struct, which would be marginally faster
	// but unnecessarily complex and error-prone.
	//
	// Instead, we'll just marshal the map as json and then unmarshal into the struct
	json, err := jsoniter.Marshal(&params)
	if err != nil {
		return fmt.Errorf("parameter json marshal failed: %v", err)
	}

	if err = jsoniter.Unmarshal(json, out); err != nil {
		return fmt.Errorf("parameter extraction failed: %v", err)
	}

	if err = validate.Struct(out); err != nil {
		return fmt.Errorf("parameter validation failed: %v", err)
	}

	return nil
}
