package omitempty

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

	"github.com/fatih/structtag"
	jsoniter "github.com/json-iterator/go"
	"github.com/modern-go/reflect2"
)

// New injects omitempty option to all fields
func New(key string) jsoniter.Extension {
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
		// Assert that the struct descriptor does not contain anonymous fields (jsoniter omits them)
		if field.Anonymous() {
			panic("Anonymous field in struct descriptor")
		}
		tag := injectOmitempty(field.Tag(), ext.key)
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

func injectOmitempty(original reflect.StructTag, key string) reflect.StructTag {
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
	// Assert jsoniter omits fields witg `-` name
	if tag.Name == "-" {
		panic("JSON-omittted field in struct descriptor")
	}
	tags.AddOptions(key, "omitempty")
	return reflect.StructTag(tags.String())
}
