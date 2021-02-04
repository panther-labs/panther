package util

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
	"github.com/aws-cloudformation/rain/cft/parse"
	"github.com/mitchellh/mapstructure"
)

// Parse a CloudFormation template and unmarshal into the out parameter.
// The out parameter must be a map or a pointer to a struct.
//
// Short-form functions like "!If" and "!Sub" will be replaced with "Fn::" objects.
func ParseTemplate(path string, out interface{}) error {
	body, err := parse.File(path)
	if err != nil {
		return err
	}
	return mapstructure.Decode(body.Map(), out)
}
