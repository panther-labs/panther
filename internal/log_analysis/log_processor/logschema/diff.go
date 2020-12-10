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
	for _, d := range DiffFields(a, b) {
		A, B := d.A, d.B
		switch {
		case A != nil && B != nil:
			if !diffWalk(&A.ValueSchema, &B.ValueSchema, walk, append(path, A.Name)) {
				return false
			}
			if A.Required != B.Required {
				ch := Change{
					Type: UpdateFieldMeta,
					Path: append(path, A.Name, "Required"),
					From: A.Required,
					To:   B.Required,
				}
				if !walk(ch) {
					return false
				}
			}
			if A.Description != B.Description {
				ch := Change{
					Type: UpdateFieldMeta,
					Path: append(path, A.Name, "Description"),
					From: A.Description,
					To:   B.Description,
				}
				if !walk(ch) {
					return false
				}
			}
		case A != nil:
			ch := Change{
				Type: DeleteField,
				Path: path,
				From: A,
			}
			if !walk(ch) {
				return false
			}
		case B != nil:
			ch := Change{
				Path: path,
				Type: AddField,
				From: nil,
				To:   B,
			}
			if !walk(ch) {
				return false
			}
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

func DiffFields(a, b []FieldSchema) (d []FieldDiff) {
	for _, f := range diffFields(a, b) {
		d = append(d, FieldDiff{A: f})
	}
	for _, f := range diffFields(b, a) {
		d = append(d, FieldDiff{B: f})
	}
	for i := range a {
		fieldA := &a[i]
		fieldB := findField(fieldA.Name, b)
		if fieldB == nil {
			continue
		}
		d = append(d, FieldDiff{A: fieldA, B: fieldB})
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

type FieldDiff struct {
	A *FieldSchema
	B *FieldSchema
}
