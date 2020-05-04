package logs

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
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
)

type FieldExtractor interface {
	ExtractFields(value string, fields *FieldBuffer) error
}

type GJSONFieldExtractor map[string]FieldExtractor

var _ FieldExtractor = (GJSONFieldExtractor)(nil)

func (g GJSONFieldExtractor) ExtractFields(value string, fields *FieldBuffer) error {
	if !gjson.Valid(value) {
		return errors.Errorf("invalid JSON value %q", value)
	}
	var err error
	for path, ext := range g {
		if ext == nil {
			continue
		}
		// nolint:scope
		gjson.Get(value, path).ForEach(func(_, jsonValue gjson.Result) bool {
			strValue := jsonValue.Str
			err = ext.ExtractFields(strValue, fields)
			return err == nil
		})
		if err != nil {
			break
		}
	}
	return nil
}
