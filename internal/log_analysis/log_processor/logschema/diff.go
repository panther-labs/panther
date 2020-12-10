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

// Change describes a change somewhere in the Tree of a ValueSchema.
type Change struct {
	Type string
	Path []string
	From interface{}
	To   interface{}
}

// nolint:lll
const (
	// AddField is the type of change when a field was added.
	AddField = "AddField"
	// DeleteField is the type of change when a field was removed.
	DeleteField = "DeleteField"
	// UpdateFieldMeta is the type of change when a field's metadata was changed (i.e. Required, Description).
	UpdateFieldMeta = "UpdateFieldMeta"
	// UpdateValue is the type of change when a field's value type has changed.
	UpdateValue = "UpdateValue"
	// UpdateValueMeta is the type of change when metadata about a field's value type has changed (i.e. TimeFormat, IsEventTime, Indicators).
	UpdateValueMeta = "UpdateValueMeta"
	// UpdateParser is the type of change when a schema's Parser has changed.
	UpdateParser = "UpdateParser"
	// UpdateMeta is the type of change when a schema's metadata has changed (i.e. Schema, Description, ReferenceURL).
	UpdateMeta = "UpdateMeta"
)

// Diff resolves a and b and returns the set of changes to go from a to b.
func Diff(from, to *Schema) ([]Change, error) {
	valueFrom, err := Resolve(from)
	if err != nil {
		return nil, err
	}

	valueTo, err := Resolve(to)
	if err != nil {
		return nil, err
	}
	c := changelog{}
	if from.Schema != to.Schema {
		c.add(UpdateMeta, from.Schema, to.Schema, "Schema")
	}
	if from.Description != to.Description {
		c.add(UpdateMeta, from.Description, to.Description, "Description")
	}
	if from.ReferenceURL != to.ReferenceURL {
		c.add(UpdateMeta, from.ReferenceURL, to.ReferenceURL, "ReferenceURL")
	}
	if !reflect.DeepEqual(from.Parser, to.Parser) {
		c.add(UpdateParser, from.Parser, to.Parser, "Parser")
	}
	DiffWalk(valueFrom, valueTo, func(ch Change) bool {
		c.changes = append(c.changes, ch)
		return true
	}, "Fields")

	return c.changes, nil
}

// DiffWalk recursively iterates two value schemas and calls `walk` when a change is found.
// The `basePath` argument is used prepended to the path on each change.
// You can abort a walk by returning false from the callback.
func DiffWalk(from, to *ValueSchema, walk func(c Change) bool, basePath ...string) {
	diffWalk(from, to, walk, basePath)
}

// diffWalk recursively iterates two value schemas and calls `walk` when a change is found.
// The `path` argument is used to attach path information on each change.
// It returns false if the walk needs to stop.
func diffWalk(from, to *ValueSchema, walk func(c Change) bool, path []string) bool {
	if from.Type != to.Type {
		ch := Change{
			Path: path,
			Type: UpdateValue,
			From: from,
			To:   to,
		}
		return walk(ch)
	}
	switch to.Type {
	case TypeObject:
		return walkObject(from.Fields, to.Fields, walk, path)
	case TypeArray:
		return diffWalk(from.Element, to.Element, walk, append(path, "*"))
	case TypeTimestamp:
		if from.IsEventTime != to.IsEventTime {
			ch := Change{
				Path: append(path, "IsEventTime"),
				Type: UpdateValueMeta,
				From: from,
				To:   to,
			}
			if !walk(ch) {
				return false
			}
		}
		if from.TimeFormat != to.TimeFormat {
			ch := Change{
				Path: append(path, "TimeFormat"),
				Type: UpdateValueMeta,
				From: from,
				To:   to,
			}
			if !walk(ch) {
				return false
			}
		}
		return true
	case TypeString:
		if from, to, changed := diffIndicators(from.Indicators, to.Indicators); changed {
			ch := Change{
				Type: UpdateValueMeta,
				Path: append(path, "Indicators"),
				From: from,
				To:   to,
			}
			return walk(ch)
		}
		return true
	default:
		return true
	}
}

func walkObject(from, to []FieldSchema, walk func(c Change) bool, path []string) bool {
	for _, d := range DiffFields(from, to) {
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

func diffIndicators(from, to []string) ([]string, []string, bool) {
	from = stringset.New(from...)
	to = stringset.New(to...)
	sort.Strings(from)
	sort.Strings(to)
	return from, to, !reflect.DeepEqual(from, to)
}

// DiffFields returns the union of all fields in both sets as list of pairs.
//
// Fields are paired by name. Each pair contains two FieldSchema pointers `A` and `B`.
// If a field is found in both `a` and `b`, `A` will point to the field in `a` and `B` will point to the field in `b`
// If a field is only found in `a`, `A` will point to the field in `a` and `B` will be nil
// If a field is only found in `b`, `A` will be nil and `B` will point to the field in `b`
//
// This function is useful to use when operating on a union of two field sets without losing information about
// the origin of each field (i.e. when diffing sets of fields)
func DiffFields(a, b []FieldSchema) (d []FieldDiff) {
	// Add fields only found in a.
	for _, f := range diffFields(a, b) {
		d = append(d, FieldDiff{A: f})
	}
	// Add fields only found in b.
	for _, f := range diffFields(b, a) {
		d = append(d, FieldDiff{B: f})
	}
	// Add fields found in both sets.
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

// diffFields returns the fields that exist in a but not in b.
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
