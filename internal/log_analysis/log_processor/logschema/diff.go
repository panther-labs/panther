package logschema

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
	"sort"

	"github.com/panther-labs/panther/pkg/stringset"
)

type Change struct {
	Type string
	Path []string
	From interface{}
	To   interface{}
}

const (
	AddField        = "AddField"
	DeleteField     = "DeleteField"
	UpdateFieldMeta = "UpdateFieldMeta"
	UpdateValue     = "UpdateValue"
	UpdateValueMeta = "UpdateValueMeta"
	UpdateParser    = "UpdateParser"
	UpdateMeta      = "UpdateMeta"
)

func Diff(a, b *Schema) ([]Change, error) {
	valueA, err := Resolve(a)
	if err != nil {
		return nil, err
	}

	valueB, err := Resolve(b)
	if err != nil {
		return nil, err
	}
	c := changelog{}
	if a.Schema != b.Schema {
		c.add(UpdateMeta, a.Schema, b.Schema, "Schema")
	}
	if a.Description != b.Description {
		c.add(UpdateMeta, a.Description, b.Description, "Description")
	}
	if a.ReferenceURL != b.ReferenceURL {
		c.add(UpdateMeta, a.ReferenceURL, b.ReferenceURL, "ReferenceURL")
	}
	if !reflect.DeepEqual(a.Parser, b.Parser) {
		c.add(UpdateParser, a.Parser, b.Parser, "Parser")
	}
	DiffWalk(valueA, valueB, func(ch Change) bool {
		c.changes = append(c.changes, ch)
		return true
	}, "Fields")

	return c.changes, nil
}

func DiffWalk(a, b *ValueSchema, walk func(c Change) bool, basePath ...string) {
	diffWalk(a, b, walk, basePath)
}

func diffWalk(a, b *ValueSchema, walk func(c Change) bool, path []string) bool {
	if a.Type != b.Type {
		ch := Change{
			Path: path,
			Type: UpdateValue,
			From: a,
			To:   b,
		}
		return walk(ch)
	}
	switch b.Type {
	case TypeObject:
		return walkObject(a.Fields, b.Fields, walk, path)
	case TypeArray:
		return diffWalk(a.Element, b.Element, walk, append(path, "*"))
	case TypeTimestamp:
		if a.IsEventTime != b.IsEventTime {
			ch := Change{
				Path: append(path, "IsEventTime"),
				Type: UpdateValueMeta,
				From: a,
				To:   b,
			}
			if !walk(ch) {
				return false
			}
		}
		if a.TimeFormat != b.TimeFormat {
			ch := Change{
				Path: append(path, "TimeFormat"),
				Type: UpdateValueMeta,
				From: a,
				To:   b,
			}
			if !walk(ch) {
				return false
			}
		}
		return true
	case TypeString:
		if a, b, changed := diffIndicators(a.Indicators, b.Indicators); changed {
			ch := Change{
				Type: UpdateValueMeta,
				Path: append(path, "Indicators"),
				From: a,
				To:   b,
			}
			return walk(ch)
		}
		return true
	default:
		return true
	}
}

func walkObject(a, b []FieldSchema, walk func(c Change) bool, path []string) bool {
	for _, f := range diffFields(a, b) {
		ch := Change{
			Type: DeleteField,
			Path: path,
			From: f,
		}
		if !walk(ch) {
			return false
		}
	}
	for _, pair := range commonFields(a, b) {
		fieldA, fieldB := pair[0], pair[1]
		if !diffWalk(&fieldA.ValueSchema, &fieldB.ValueSchema, walk, append(path, fieldA.Name)) {
			return false
		}
		if fieldA.Required != fieldB.Required {
			ch := Change{
				Type: UpdateFieldMeta,
				Path: append(path, fieldA.Name, "Required"),
				From: fieldA.Required,
				To:   fieldB.Required,
			}
			if !walk(ch) {
				return false
			}
		}
		if fieldA.Description != fieldB.Description {
			ch := Change{
				Type: UpdateFieldMeta,
				Path: append(path, fieldA.Name, "Description"),
				From: fieldA.Description,
				To:   fieldB.Description,
			}
			if !walk(ch) {
				return false
			}
		}
	}
	for _, f := range diffFields(b, a) {
		ch := Change{
			Path: path,
			Type: AddField,
			From: nil,
			To:   f,
		}
		if !walk(ch) {
			return false
		}
	}
	return true
}

func diffIndicators(a, b []string) ([]string, []string, bool) {
	a = stringset.New(a...)
	b = stringset.New(b...)
	sort.Strings(a)
	sort.Strings(b)
	return a, b, !reflect.DeepEqual(a, b)
}

func commonFields(a, b []FieldSchema) (common [][2]*FieldSchema) {
	for i := range a {
		fieldA := &a[i]
		fieldB := findField(fieldA.Name, b)
		if fieldB == nil {
			continue
		}
		pair := [2]*FieldSchema{fieldA, fieldB}
		common = append(common, pair)
	}
	return
}
func diffFields(a, b []FieldSchema) (d []*FieldSchema) {
	for i := range a {
		fieldA := &a[i]
		fieldB := findField(fieldA.Name, b)
		if fieldB == nil {
			d = append(d, fieldA)
		}
	}
	return
}

type changelog struct {
	changes []Change
}

func (c *changelog) add(typ string, from, to interface{}, path ...string) {
	c.changes = append(c.changes, Change{
		Type: typ,
		Path: append(make([]string, 0, len(path)), path...),
		From: from,
		To:   to,
	})
}

func findField(name string, fields []FieldSchema) *FieldSchema {
	if i := indexOfField(name, fields); 0 <= i && i < len(fields) {
		return &fields[i]
	}
	return nil
}

func indexOfField(name string, fields []FieldSchema) int {
	for i := range fields {
		if fields[i].Name == name {
			return i
		}
	}
	return -1
}
