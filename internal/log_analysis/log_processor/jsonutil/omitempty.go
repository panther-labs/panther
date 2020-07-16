package jsonutil

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

	"github.com/fatih/structtag"
	jsoniter "github.com/json-iterator/go"
	"github.com/modern-go/reflect2"
)

// NewOmitempty injects omitempty option to all fields
func NewOmitempty(key string) jsoniter.Extension {
	if key == "" {
		key = "json"
	}
	return &omitemptyExt{
		key: key,
	}
}

type omitemptyExt struct {
	jsoniter.DummyExtension
	key string
}

func (ext *omitemptyExt) UpdateStructDescriptor(desc *jsoniter.StructDescriptor) {
	for _, binding := range desc.Fields {
		field := binding.Field
		if field.Anonymous() {
			continue
		}
		tag := InjectOmitempty(field.Tag(), ext.key)
		binding.Field = InjectTag(field, tag)
	}
}

func InjectTag(field reflect2.StructField, tag reflect.StructTag) reflect2.StructField {
	return &fieldExt{
		StructField: field,
		tag:         tag,
	}
}

type fieldExt struct {
	reflect2.StructField
	tag reflect.StructTag
}

func (ext *fieldExt) Tag() reflect.StructTag {
	if ext.tag != "" {
		return ext.tag
	}
	return ext.StructField.Tag()
}

func InjectOmitempty(original reflect.StructTag, key string) reflect.StructTag {
	tags, err := structtag.Parse(string(original))
	if err != nil {
		return original
	}
	tag, err := tags.Get(key)
	if err != nil {
		tag := structtag.Tag{
			Key:     key,
			Options: []string{"omitempty"},
		}
		_ = tags.Set(&tag)
		return reflect.StructTag(tags.String())
	}
	if tag.Name == "-" {
		return original
	}
	tags.AddOptions(key, "omitempty")
	return reflect.StructTag(tags.String())
}
