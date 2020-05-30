package object

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
	"bytes"

	"github.com/tidwall/gjson"

	"github.com/panther-labs/panther/pkg/extract"
)

// Object is used to represent an arbitrary JSON object
type Object []byte

var (
	emptyMap = []byte(`{}`)
	nullMap  = []byte(`null`)
)

func NewObject(jsonString string) *Object {
	obj := (Object)(jsonString)
	return &obj
}

func (obj *Object) String() string {
	if obj == nil {
		return ""
	}
	return string(*obj)
}

func (obj *Object) MarshalJSON() ([]byte, error) {
	objBytes := []byte(*obj)
	if len(objBytes) == 0 || bytes.Equal(emptyMap, objBytes) || bytes.Equal(nullMap, objBytes) {
		return nullMap, nil
	}
	return objBytes, nil
}

func (obj *Object) UnmarshalJSON(objBytes []byte) (err error) {
	if len(objBytes) == 0 || bytes.Equal(emptyMap, objBytes) || bytes.Equal(nullMap, objBytes) {
		return nil
	}
	*obj = objBytes
	return nil
}

func (obj *Object) Extract(extractors ...extract.Extractor) {
	if obj == nil {
		return
	}
	result := gjson.ParseBytes(*obj)
	extract.Parsed(result, extractors...)
}
